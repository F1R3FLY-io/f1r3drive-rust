//! Protobuf-generated clients for the f1r3node gRPC APIs.
//!
//! Vendored verbatim from `f1r3node-rust/models/src/main/protobuf/` so that
//! wire encoding stays byte-identical. Compiled by `build.rs` via
//! `tonic-prost-build`.
//!
//! Four packages are generated:
//! - [`casper`]: core messages from `CasperMessage.proto` + `DeployServiceCommon.proto`.
//! - [`casper::v1`]: the `DeployService` and `ProposeService` gRPC clients.
//! - [`rhoapi`]: Par and friends from `RhoTypes.proto` — what deploys and
//!   exploratory replies encode in.
//! - [`servicemodelapi`]: service-level error enum from `ServiceError.proto`.
#![allow(clippy::all)]

pub mod casper {
    tonic::include_proto!("casper");
    pub mod v1 {
        tonic::include_proto!("casper.v1");
    }
}

pub mod rhoapi {
    tonic::include_proto!("rhoapi");
}

pub mod servicemodelapi {
    tonic::include_proto!("servicemodelapi");
}

pub mod scalapb {
    tonic::include_proto!("scalapb");
}
