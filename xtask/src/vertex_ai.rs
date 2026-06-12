// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Context, Result};
use google_cloud_aiplatform_v1::client::PredictionService;
use google_cloud_aiplatform_v1::model::{
    part::Data as PartData, Content, GenerateContentRequest, Part,
};

fn detect_project() -> String {
    std::env::var("GCP_PROJECT").unwrap_or_else(|_| "caliptra-github-ci".to_string())
}

pub fn prompt(
    prompt_text: &str,
    model: &str,
    project: Option<String>,
    location: &str,
) -> Result<()> {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to build tokio runtime")?;

    rt.block_on(async {
        let endpoint = format!("https://{}-aiplatform.googleapis.com", location);
        let client = PredictionService::builder()
            .with_endpoint(endpoint)
            .build()
            .await
            .context("Failed to build PredictionService client")?;

        let project = match project {
            Some(p) => p,
            None => detect_project(),
        };

        // Model path format: projects/{project}/locations/{location}/publishers/google/models/{model}
        let model_path = format!(
            "projects/{}/locations/{}/publishers/google/models/{}",
            project, location, model
        );

        let mut part = Part::default();
        part.data = Some(PartData::Text(prompt_text.to_string()));

        let mut content = Content::default();
        content.role = "user".to_string();
        content.parts = vec![part];

        let mut req = GenerateContentRequest::default();
        req.model = model_path;
        req.contents = vec![content];

        let response = client
            .generate_content()
            .with_request(req)
            .send()
            .await
            .context("Failed to call generate_content")?;

        // Parse response to get text
        let candidate = response
            .candidates
            .first()
            .ok_or_else(|| anyhow!("No candidates in response"))?;
        let content = candidate
            .content
            .as_ref()
            .ok_or_else(|| anyhow!("No content in candidate"))?;
        let part = content
            .parts
            .first()
            .ok_or_else(|| anyhow!("No parts in content"))?;

        match &part.data {
            Some(PartData::Text(text)) => {
                println!("{}", text);
                Ok(())
            }
            _ => Err(anyhow!("Expected text part in response")),
        }
    })
}
