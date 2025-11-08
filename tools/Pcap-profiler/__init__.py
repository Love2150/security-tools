{
  "default_profile": "default",
  "profiles": {
    "default": {
      "top": 10,
      "decode": [
        "tcp.port==36050,http"
      ],
      "http_ports": [8080, 8888],
      "tls_ports": [8443]
    },
    "work": {
      "top": 15,
      "decode": [
        "tcp.port==9000,http",
        "tcp.port==9443,tls"
      ]
    }
  }
}
