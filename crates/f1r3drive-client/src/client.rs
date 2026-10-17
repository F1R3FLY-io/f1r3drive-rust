//! `NodeClient`: a thin wrapper over the generated tonic clients that
//! exposes just the four methods we need for FUSE: `exploratory_deploy`,
//! `do_deploy`, `propose`, `is_finalized`.

use f1r3drive_proto::casper::v1::deploy_service_client::DeployServiceClient;
use f1r3drive_proto::casper::v1::propose_service_client::ProposeServiceClient;
use f1r3drive_proto::casper::v1::{
    deploy_response, exploratory_deploy_response, is_finalized_response, propose_response,
    status_response, DeployResponse, ExploratoryDeployResponse, IsFinalizedResponse,
    ProposeResponse, StatusResponse,
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

/// Cloning a `NodeClient` is cheap: tonic's `Channel` is Arc-backed, so
/// `.clone()` is essentially a refcount bump. Daemons that need
/// concurrent gRPC calls should clone per-request rather than
/// serializing through a shared `Mutex<NodeClient>`.
#[derive(Clone)]
pub struct NodeClient {
    deploy: DeployServiceClient<Channel>,
    propose: ProposeServiceClient<Channel>,
}

impl NodeClient {
    /// Connect with Deploy on `host:port` and Propose on the same host
    /// but `port + 1`. Mirrors the f1r3node layout: the external port
    /// hosts only DeployService, the internal (external + 1) hosts
    /// Propose + Repl + Lsp.
    pub async fn connect(host: &str, port: u16) -> Result<Self, ClientError> {
        Self::connect_split(host, port, host, port + 1).await
    }

    /// Connect Deploy and Propose to independent `(host, port)` pairs.
    /// Use when the node's external and internal gRPC endpoints aren't
    /// adjacent (e.g. a reverse proxy fanning out services).
    pub async fn connect_split(
        deploy_host: &str,
        deploy_port: u16,
        propose_host: &str,
        propose_port: u16,
    ) -> Result<Self, ClientError> {
        let deploy_ep = format!("http://{deploy_host}:{deploy_port}");
        let propose_ep = format!("http://{propose_host}:{propose_port}");
        let deploy_ch = Channel::from_shared(deploy_ep)
            .map_err(|e| ClientError::Sign(format!("bad deploy endpoint: {e}")))?
            .connect()
            .await?;
        let propose_ch = Channel::from_shared(propose_ep)
            .map_err(|e| ClientError::Sign(format!("bad propose endpoint: {e}")))?
            .connect()
            .await?;
        Ok(Self {
            deploy: DeployServiceClient::new(deploy_ch),
            propose: ProposeServiceClient::new(propose_ch),
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

    /// Pull the node's current status: shardId, LFB number, peer counts,
    /// etc. The daemon uses `last_finalized_block_number` as the floor
    /// for a `valid_after_block_number` on signed deploys — a deploy
    /// older than `(LFB − lifespan)` is rejected at admission.
    pub async fn status(&mut self) -> Result<StatusInfo, ClientError> {
        let resp = self.deploy.status(()).await?.into_inner();
        unwrap_status_response(resp)
    }
}

/// Narrow projection of the node's status payload. We only expose the
/// fields the daemon actually consumes.
#[derive(Debug, Clone)]
pub struct StatusInfo {
    pub shard_id: String,
    pub last_finalized_block_number: i64,
    pub is_ready: bool,
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

fn unwrap_status_response(resp: StatusResponse) -> Result<StatusInfo, ClientError> {
    match resp.message {
        Some(status_response::Message::Status(s)) => Ok(StatusInfo {
            shard_id: s.shard_id,
            last_finalized_block_number: s.last_finalized_block_number,
            is_ready: s.is_ready,
        }),
        Some(status_response::Message::Error(e)) => Err(service_err(e.messages)),
        None => Err(ClientError::ServiceError("empty StatusResponse".into())),
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
