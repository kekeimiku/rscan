use rscan::{ms17_010, smbghost};
use tokio::time;

#[tokio::main]
async fn main() {
    let list = vec![
        "192.168.31.30:445",
        "192.168.31.31:445",
        "192.168.31.196:445",
        "192.168.31.241:445",
    ];

    let duration = tokio::time::Duration::from_secs(1);

    let handles = list
        .iter()
        .map(|ip| tokio::spawn(time::timeout(duration, ms17_010::run(ip))))
        .collect::<Vec<_>>();

    for h in handles {
        println!("{:?}", h.await);
    }

    let handles = list
        .iter()
        .map(|ip| tokio::spawn(time::timeout(duration, smbghost::run(ip))))
        .collect::<Vec<_>>();

    for h in handles {
        println!("{:?}", h.await);
    }
}
