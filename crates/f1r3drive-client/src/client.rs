//! `NodeClient`: a thin wrapper over the generated tonic clients that
//! exposes just the four methods we need for FUSE: `exploratory_deploy`,
//! `do_deploy`, `propose`, `is_finalized`.

use f1r3drive_proto::casper::v1::deploy_service_client::DeployServiceClient;
use f1r3drive_proto::casper::v1::propose_service_client::ProposeServiceClient;
use f1r3drive_proto::casper::v1::{
    deploy_response, exploratory_deploy_response, is_finalized_response, propose_response,
    DeployResponse, ExploratoryDeployResponse, IsFinalizedResponse, ProposeResponse,
};
use f1r3drive_proto::casper::{
    DeployDataProto, ExploratoryDeployQuery, IsFinalizedQuery, ProposeQuery,
};
use f1r3drive_proto::rhoapi::Par;
use tonic::transport::Channel;

use crate::error::ClientError;

/// Successful result of a doDeploy call. The server returns a human-readable
/// string containing the deploy signature; we re-expose it unchanged.
#[derive(Debug, Clone)]
pub struct DeployAck {
    pub message: String,
}

/// Successful result of an exploratory_deploy call.
#[derive(Debug, Clone)]
pub struct ExploratoryResult {
    pub pars: Vec<Par>,
    pub cost: u64,
}

/// Successful result of a propose call.
#[derive(Debug, Clone)]
pub struct ProposeAck {
    pub message: String,
}

#[derive(Clone)]
pub struct NodeClient {
    deploy: DeployServiceClient<Channel>,
    propose: ProposeServiceClient<Channel>,
}

impl NodeClient {
    /// Connect to the f1r3node at `http://{host}:{port}`.
    pub async fn connect(host: &str, port: u16) -> Result<Self, ClientError> {
        let endpoint = format!("http://{host}:{port}");
        let channel = Channel::from_shared(endpoint)
            .map_err(|e| ClientError::Sign(format!("bad endpoint: {e}")))?
            .connect()
            .await?;
        Ok(Self {
            deploy: DeployServiceClient::new(channel.clone()),
            propose: ProposeServiceClient::new(channel),
        })
    }

    /// Submit a signed deploy via `DeployService.doDeploy`.
    pub async fn do_deploy(&mut self, signed: DeployDataProto) -> Result<DeployAck, ClientError> {
        let resp = self.deploy.do_deploy(signed).await?.into_inner();
        unwrap_deploy_response(resp)
    }

    /// Run a read-only Rholang query via `DeployService.exploratoryDeploy`.
    /// Pass empty string for the latest LFB.
    pub async fn exploratory_deploy(
        &mut self,
        term: &str,
        block_hash: &str,
        use_pre_state_hash: bool,
    ) -> Result<ExploratoryResult, ClientError> {
        let query = ExploratoryDeployQuery {
            term: term.to_string(),
            block_hash: block_hash.to_string(),
            use_pre_state_hash,
        };
        let resp = self.deploy.exploratory_deploy(query).await?.into_inner();
        unwrap_exploratory_response(resp)
    }

    /// Trigger block creation via `ProposeService.propose`.
    pub async fn propose(&mut self, is_async: bool) -> Result<ProposeAck, ClientError> {
        let resp = self
            .propose
            .propose(ProposeQuery { is_async })
            .await?
            .into_inner();
        unwrap_propose_response(resp)
    }

    /// Check whether a block hash is in the finalized tip set.
    pub async fn is_finalized(&mut self, block_hash: &str) -> Result<bool, ClientError> {
        let resp = self
            .deploy
            .is_finalized(IsFinalizedQuery {
                hash: block_hash.to_string(),
            })
            .await?
            .into_inner();
        unwrap_is_finalized_response(resp)
    }
}

fn unwrap_deploy_response(resp: DeployResponse) -> Result<DeployAck, ClientError> {
    match resp.message {
        Some(deploy_response::Message::Result(s)) => Ok(DeployAck { message: s }),
        Some(deploy_response::Message::Error(e)) => Err(service_err(e.messages)),
        None => Err(ClientError::ServiceError("empty DeployResponse".into())),
    }
}

fn unwrap_exploratory_response(
    resp: ExploratoryDeployResponse,
) -> Result<ExploratoryResult, ClientError> {
    let cost = resp.cost;
    match resp.message {
        Some(exploratory_deploy_response::Message::Result(data)) => Ok(ExploratoryResult {
            pars: data.post_block_data,
            cost,
        }),
        Some(exploratory_deploy_response::Message::Error(e)) => Err(service_err(e.messages)),
        None => Err(ClientError::ServiceError(
            "empty ExploratoryDeployResponse".into(),
        )),
    }
}

fn unwrap_propose_response(resp: ProposeResponse) -> Result<ProposeAck, ClientError> {
    match resp.message {
        Some(propose_response::Message::Result(s)) => Ok(ProposeAck { message: s }),
        Some(propose_response::Message::Error(e)) => Err(service_err(e.messages)),
        None => Err(ClientError::ServiceError("empty ProposeResponse".into())),
    }
}

fn unwrap_is_finalized_response(resp: IsFinalizedResponse) -> Result<bool, ClientError> {
    match resp.message {
        Some(is_finalized_response::Message::IsFinalized(b)) => Ok(b),
        Some(is_finalized_response::Message::Error(e)) => Err(service_err(e.messages)),
        None => Err(ClientError::ServiceError(
            "empty IsFinalizedResponse".into(),
        )),
    }
}

fn service_err(messages: Vec<String>) -> ClientError {
    let joined = if messages.is_empty() {
        "unspecified".to_string()
    } else {
        messages.join("; ")
    };
    ClientError::ServiceError(joined)
}
