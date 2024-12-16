use axum::response::Response;
use compute_api::responses::InfoResponse;
use http::StatusCode;

use crate::http::JsonResponse;

pub(in crate::http) async fn get_info() -> Response {
    let num_cpus = num_cpus::get_physical();
    JsonResponse::success(StatusCode::OK, &InfoResponse { num_cpus })
}
