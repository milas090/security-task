# Unmanaged instance group that wraps the single backend VM
resource "google_compute_instance_group" "backend_group" {
  name = "backend-group"
  zone = "${var.region}-a"

  # The VM we created earlier becomes a member of this group
  instances = [
    google_compute_instance.backend_vm.self_link,
  ]
}

# HTTP health check for the backend instances (port 80)
resource "google_compute_health_check" "backend_http" {
  name = "backend-http-health-check"

  http_health_check {
    port = 80
  }
}

# Backend service that ties the instance group + health check together
resource "google_compute_backend_service" "backend_service" {
  name                  = "backend-service"
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30

  # LB will use this health check to decide if backends are healthy
  health_checks = [
    google_compute_health_check.backend_http.self_link,
  ]

  # This backend pool uses the instance group as its backends
  backend {
    group = google_compute_instance_group.backend_group.self_link
  }
}
