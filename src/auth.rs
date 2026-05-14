use anyhow::{Result, anyhow};
use get_if_addrs::{IfAddr, get_if_addrs};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::{Agent, ResponseExt};
use url::Url;

use crate::classifier::Classifier;

const NET_AUTH_BASEURL: &str = "https://net-auth.shanghaitech.edu.cn:19008";
const CAPTIVE_PROBES: &[CaptiveProbe] = &[
    CaptiveProbe {
        url: "http://captive.apple.com/hotspot-detect.html",
        expected_status: 200,
        expected_body: Some("Success"),
    },
    CaptiveProbe {
        url: "http://connectivitycheck.gstatic.com/generate_204",
        expected_status: 204,
        expected_body: None,
    },
    CaptiveProbe {
        url: "http://www.msftconnecttest.com/connecttest.txt",
        expected_status: 200,
        expected_body: Some("Microsoft Connect Test"),
    },
];

struct CaptiveProbe {
    url: &'static str,
    expected_status: u16,
    expected_body: Option<&'static str>,
}

enum CaptivePortalState {
    AuthenticationRequired,
    NoAuthenticationRequired,
    ConnectivityFailed(String),
    Indeterminate(String),
}

#[derive(Debug, PartialEq)]
pub enum NetworkState {
    AuthenticationRequired,
    NoAuthenticationRequired,
    ConnectivityFailed(String),
}

#[derive(Debug, PartialEq)]
pub enum AuthResult {
    InvalidVerifyCode,
    UserNotFound,
    InvalidPassword(i64, u64),
    UserLocked(u64),
    Success,
}

#[derive(Clone, Debug)]
struct PageParams {
    push_page_id: String,
    ssid: String,
    uaddress: Option<String>,
}

#[derive(Debug, Error)]
pub enum AuthParseError {
    #[error("Response missing field: {0}")]
    FieldNotFound(String),
    #[error("Unsupported error code: {0}")]
    UnsupportedErrorCode(String),
}

pub struct Authenticator {
    user_id: String,
    password: String,
    uaddresses: Vec<String>,
    classifier: Classifier,
    client: Agent,
}

impl Authenticator {
    pub fn new(user_id: String, password: String, classifier: Classifier) -> Result<Self> {
        let client = Self::build_client();
        let uaddresses = Self::get_uaddress_candidates()?;

        Ok(Self {
            user_id,
            password,
            uaddresses,
            classifier,
            client,
        })
    }

    pub fn network_state() -> Result<NetworkState> {
        let client = Self::build_client();
        let uaddresses = Self::get_uaddress_candidates()?;

        match Self::check_captive_portal(&client) {
            CaptivePortalState::AuthenticationRequired => Ok(NetworkState::AuthenticationRequired),
            CaptivePortalState::NoAuthenticationRequired => {
                Ok(NetworkState::NoAuthenticationRequired)
            }
            CaptivePortalState::ConnectivityFailed(reason) => {
                Ok(NetworkState::ConnectivityFailed(reason))
            }
            CaptivePortalState::Indeterminate(reason) => {
                if uaddresses.is_empty() {
                    Ok(NetworkState::ConnectivityFailed(format!(
                        "No uaddress candidate found and captive portal probes were inconclusive: {}",
                        reason
                    )))
                } else {
                    log::warn!(
                        "Captive portal probes were inconclusive, continuing with authentication: {}",
                        reason
                    );
                    Ok(NetworkState::AuthenticationRequired)
                }
            }
        }
    }

    fn build_client() -> Agent {
        let tls_config = TlsConfig::builder()
            .provider(if cfg!(feature = "native-tls") {
                TlsProvider::NativeTls
            } else {
                TlsProvider::Rustls
            })
            .build();

        let client = Agent::config_builder()
            .tls_config(tls_config)
            .timeout_global(Some(Duration::from_secs(10)))
            .build()
            .into();

        client
    }

    pub fn perform_login(&self) -> Result<()> {
        let probe_params = self.get_page_params_from_probe().ok();
        let mut uaddresses = self.uaddresses.clone();

        if let Some(uaddress) = probe_params
            .as_ref()
            .and_then(|page_params| page_params.uaddress.clone())
        {
            uaddresses.insert(0, uaddress);
        }

        uaddresses.dedup();

        if let Some(page_params) = probe_params {
            let uaddress = page_params
                .uaddress
                .clone()
                .or_else(|| uaddresses.first().cloned())
                .ok_or_else(|| {
                    anyhow!(
                        "Authentication is required, but no uaddress was found in the portal redirect, EGATE_UADDRESS/EGATE_IP, or local network interfaces"
                    )
                })?;

            log::info!("Logining for uaddress: {}", uaddress);
            self.login_with_page_params(&uaddress, page_params)?;
            return Ok(());
        }

        if uaddresses.is_empty() {
            return Err(anyhow!(
                "Authentication is required, but no uaddress candidate was found. Set EGATE_UADDRESS to the campus-facing IP address if this device is behind a router."
            ));
        }

        for uaddress in &uaddresses {
            log::info!("Logining for uaddress: {}", uaddress);
            self.login_for_uaddress(uaddress)?;
        }
        Ok(())
    }
}

impl Authenticator {
    fn check_captive_portal(client: &Agent) -> CaptivePortalState {
        let mut saw_response = false;
        let mut last_error = String::new();

        for probe in CAPTIVE_PROBES {
            log::info!("Trying captive probe: {}", probe.url);
            match client.get(probe.url).call() {
                Ok(mut response) => {
                    saw_response = true;
                    let final_url = response.get_uri().to_string();
                    log::info!("Probe final URL: {}", final_url);

                    if Self::parse_page_params_from_url(&final_url).is_ok() {
                        return CaptivePortalState::AuthenticationRequired;
                    }

                    let status = response.status().as_u16();
                    let body_matches = match probe.expected_body {
                        Some(expected_body) => response
                            .body_mut()
                            .read_to_string()
                            .map(|body| body.contains(expected_body))
                            .unwrap_or(false),
                        None => true,
                    };

                    if status == probe.expected_status && body_matches {
                        return CaptivePortalState::NoAuthenticationRequired;
                    }

                    last_error = format!(
                        "Probe {} returned status {} and final URL {} without login parameters",
                        probe.url, status, final_url
                    );
                }
                Err(err) => {
                    last_error = format!("Probe {} request failed: {}", probe.url, err);
                }
            }
        }

        if saw_response {
            CaptivePortalState::Indeterminate(last_error)
        } else {
            CaptivePortalState::ConnectivityFailed(last_error)
        }
    }

    fn parse_page_params_from_url(final_url: &str) -> Result<PageParams> {
        let redirected_url = Url::parse(final_url)?;
        let query_params: HashMap<_, _> = redirected_url.query_pairs().into_owned().collect();

        let push_page_id = query_params
            .get("pushPageId")
            .ok_or(anyhow!("Cannot find pushPageId in query parameters"))?
            .to_string();
        let ssid = query_params
            .get("ssid")
            .ok_or(anyhow!("Cannot find ssid in query parameters"))?
            .to_string();

        let uaddress = [
            "uaddress",
            "userip",
            "userIp",
            "userAddress",
            "wlanuserip",
            "wlanUserIp",
        ]
        .into_iter()
        .find_map(|field| query_params.get(field).cloned());

        Ok(PageParams {
            push_page_id,
            ssid,
            uaddress,
        })
    }

    fn get_page_params_from_probe(&self) -> Result<PageParams> {
        let mut last_error = String::new();

        for probe in CAPTIVE_PROBES {
            log::info!("Trying captive probe: {}", probe.url);
            match self.client.get(probe.url).call() {
                Ok(response) => {
                    let final_url = response.get_uri().to_string();
                    log::info!("Probe final URL: {}", final_url);

                    match Self::parse_page_params_from_url(&final_url) {
                        Ok(page_params) => {
                            log::info!("Get pushPageId from probe: {:?}", page_params.push_page_id);
                            log::info!("Get ssid from probe: {:?}", page_params.ssid);
                            log::info!("Get uaddress from probe: {:?}", page_params.uaddress);
                            return Ok(page_params);
                        }
                        Err(err) => {
                            last_error = format!(
                                "Probe {} did not provide login params, final URL: {}, error: {}",
                                probe.url, final_url, err
                            );
                        }
                    }
                }
                Err(err) => {
                    last_error = format!("Probe {} request failed: {}", probe.url, err);
                }
            }
        }

        Err(anyhow!(
            "Cannot get pushPageId/ssid from captive probes. Last error: {}",
            last_error
        ))
    }

    fn get_uaddress_candidates() -> Result<Vec<String>> {
        let mut uaddresses = Vec::new();

        if let Ok(uaddress) = env::var("EGATE_UADDRESS").or_else(|_| env::var("EGATE_IP")) {
            if !uaddress.is_empty() && !uaddresses.contains(&uaddress) {
                uaddresses.push(uaddress);
            }
        }

        for uaddress in get_if_addrs()?
            .into_iter()
            .filter_map(|if_addr| match if_addr.addr {
                IfAddr::V4(ipv4) if !ipv4.ip.is_loopback() => Some(ipv4.ip.to_string()),
                _ => None,
            })
        {
            if !uaddresses.contains(&uaddress) {
                uaddresses.push(uaddress);
            }
        }

        log::info!("uaddress candidates: {:?}", uaddresses);

        Ok(uaddresses)
    }

    fn get_verify_code(&self, uaddress: &str) -> Result<String> {
        let image_url = format!(
            "{}/portalauth/verificationcode?uaddress={}",
            NET_AUTH_BASEURL, uaddress
        );

        let image = self
            .client
            .get(&image_url)
            .call()?
            .body_mut()
            .read_to_vec()?;

        let verify_code = self.classifier.classification(&image)?;
        log::info!("Verify code: {}", verify_code);

        Ok(verify_code)
    }

    fn get_page_params(&self, uaddress: &str) -> Result<PageParams> {
        if let Ok(page_params) = self.get_page_params_from_probe() {
            return Ok(page_params);
        }

        let verify_url = format!("{}/portal?uaddress={}&ac-ip=0", NET_AUTH_BASEURL, uaddress);

        let response = self.client.get(&verify_url).call()?;
        let final_url = response.get_uri().to_string();
        let page_params = Self::parse_page_params_from_url(&final_url)?;

        log::info!("Get pushPageId: {:?}", page_params.push_page_id);
        log::info!("Get ssid: {:?}", page_params.ssid);
        log::info!("Get uaddress: {:?}", page_params.uaddress);

        Ok(page_params)
    }

    fn parse_auth_result(&self, json_value: &serde_json::Value) -> Result<AuthResult> {
        if json_value["success"]
            .as_bool()
            .ok_or(AuthParseError::FieldNotFound("success".to_string()))?
        {
            return Ok(AuthResult::Success);
        }

        let error_code = json_value["errorcode"]
            .as_str()
            .ok_or(AuthParseError::FieldNotFound("errorcode".to_string()))?
            .parse::<u64>()?;

        let response_data = &json_value["data"];

        fn parse_field<T: FromStr>(response_data: &serde_json::Value, field: &str) -> Result<T>
        where
            <T as FromStr>::Err: Error + Send + Sync + 'static,
        {
            let parse_result = response_data[field]
                .as_str()
                .ok_or(AuthParseError::FieldNotFound(field.to_string()))?
                .parse::<T>()?;

            Ok(parse_result)
        }

        match error_code {
            3010 => Ok(AuthResult::InvalidVerifyCode),
            10505 => {
                let remain_lock_time = parse_field(response_data, "remainLockTime")?;
                Ok(AuthResult::UserLocked(remain_lock_time))
            }
            10503 => {
                if response_data.is_null() {
                    Ok(AuthResult::UserNotFound)
                } else {
                    let remain_times = parse_field(response_data, "remainTimes")?;
                    let lock_time = parse_field(response_data, "lockTime")?;
                    Ok(AuthResult::InvalidPassword(remain_times, lock_time))
                }
            }
            _ => Err(AuthParseError::UnsupportedErrorCode(error_code.to_string()).into()),
        }
    }

    fn login_for_uaddress(&self, uaddress: &str) -> Result<()> {
        let page_params = self.get_page_params(uaddress)?;
        self.login_with_page_params(uaddress, page_params)
    }

    fn login_with_page_params(
        &self,
        fallback_uaddress: &str,
        page_params: PageParams,
    ) -> Result<()> {
        let uaddress = page_params.uaddress.as_deref().unwrap_or(fallback_uaddress);

        loop {
            let verify_code = self.get_verify_code(uaddress)?;

            let json_value = self
                .client
                .post(&format!("{}/portalauth/login", NET_AUTH_BASEURL))
                .send_form([
                    ("userName", &self.user_id),
                    ("userPass", &self.password),
                    ("uaddress", &uaddress.to_string()),
                    ("validCode", &verify_code),
                    ("pushPageId", &page_params.push_page_id),
                    ("ssid", &page_params.ssid),
                    ("agreed", &String::from("1")),
                    ("authType", &String::from("1")),
                ])?
                .body_mut()
                .read_to_string()?;

            let auth_result = self.parse_auth_result(&serde_json::from_str(&json_value)?)?;

            match auth_result {
                AuthResult::Success => {
                    log::info!("Login successful for uaddress: {}", uaddress);
                    break;
                }
                AuthResult::InvalidVerifyCode => {
                    log::warn!("Invalid verify code: {}, retrying...", verify_code)
                }
                AuthResult::UserNotFound => {
                    log::warn!("User not found: {}", self.user_id);
                    return Err(anyhow!("User not found"));
                }
                AuthResult::UserLocked(remain_lock_time) => {
                    log::warn!(
                        "You are locked. Remaining lock time {} minutes",
                        remain_lock_time
                    );
                    return Err(anyhow!("User locked"));
                }
                AuthResult::InvalidPassword(remain_times, lock_time) => {
                    log::warn!(
                        "Invalid password. Enter the wrong password {} more times and you will be locked out for {} minutes",
                        remain_times,
                        lock_time
                    );
                    return Err(anyhow!("Invalid password"));
                }
            }
        }

        Ok(())
    }
}
