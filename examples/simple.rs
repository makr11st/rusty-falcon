use rusty_falcon::apis::incidents_api::{crowd_score};
use rusty_falcon::easy::client::{FalconHandle, Credentials};

#[tokio::main]
async fn main() {
    let falcon = FalconHandle::from_cfg(Credentials::from_env().unwrap())
        .await
        .expect("Could not authenticate with CrowdStrike API");

    let crowd_score_response = crowd_score(&falcon.cfg, None, None, None, None)
        .await
        .expect("Could not fetch CrowdScore");

    if ! crowd_score_response.errors.is_empty() {
        eprintln!("Errors occured while calculating CrowdScore: {:?}", crowd_score_response.errors);
    }

    if crowd_score_response.resources.is_empty() {
        eprintln!("No CrowdScore returned")
    }

    let score = crowd_score_response.resources.last().unwrap();
    println!("As of {} your CrowdScore is {}.", score.timestamp, score.score)
}
