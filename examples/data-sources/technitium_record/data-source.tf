data "technitium_record" "web" {
  zone = "example.com"
  name = "www.example.com"
  type = "A"
}

output "web_ip" {
  value = data.technitium_record.web.value
}
