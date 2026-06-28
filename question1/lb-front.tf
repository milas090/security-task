resource "google_compute_managed_ssl_certificate" "default" {
  name = "backend-ssl-cert"

  managed {
    domains = [var.domain_name]
  }
}

resource "google_compute_url_map" "default" {
  name            = "backend-url-map"
  default_service = google_compute_backend_service.backend_service.self_link
}

resource "google_compute_target_https_proxy" "https_proxy" {
  name             = "backend-https-proxy"
  url_map          = google_compute_url_map.default.self_link
  ssl_certificates = [google_compute_managed_ssl_certificate.default.self_link]
}

resource "google_compute_global_forwarding_rule" "https_forwarding_rule" {
  name        = "https-forwarding-rule"
  target      = google_compute_target_https_proxy.https_proxy.self_link
  port_range  = "443"
  ip_protocol = "TCP"
}
