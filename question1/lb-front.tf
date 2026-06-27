resource "google_compute_url_map" "default" {
  name            = "backend-url-map"
  default_service = google_compute_backend_service.backend_service.self_link
}

resource "google_compute_target_http_proxy" "http_proxy" {
  name    = "backend-http-proxy"
  url_map = google_compute_url_map.default.self_link
}

resource "google_compute_global_forwarding_rule" "http_forwarding_rule" {
  name        = "http-forwarding-rule"
  target      = google_compute_target_http_proxy.http_proxy.self_link
  port_range  = "80"
  ip_protocol = "TCP"
}
