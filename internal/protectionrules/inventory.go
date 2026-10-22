// Frozen A1 writable inventory, 2026-10-22. Future stages are explicitly inventoried.
package protectionrules

const inventory = `{
  "brute-force-protection": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "enabled": {
        "type": "boolean"
      },
      "shields": {
        "type": "array",
        "items": {
          "type": "string",
          "enum": [
            "block",
            "user_notification"
          ]
        }
      },
      "allowlist": {
        "type": "array",
        "items": {
          "type": "string",
          "anyOf": [
            {
              "type": "string",
              "format": "ipv4"
            },
            {
              "type": "string",
              "format": "cidr"
            },
            {
              "type": "string",
              "format": "ipv6"
            },
            {
              "type": "string",
              "format": "ipv6_cidr"
            }
          ]
        }
      },
      "mode": {
        "type": "string",
        "default": "count_per_identifier_and_ip",
        "enum": [
          "count_per_identifier_and_ip",
          "count_per_identifier"
        ]
      },
      "max_attempts": {
        "type": "integer",
        "default": 10,
        "minimum": 1,
        "maximum": 100
      },
      "form_submission_mode": {
        "type": "string",
        "enum": [
          "auto",
          "manual"
        ]
      }
    }
  },
  "suspicious-ip-throttling": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "enabled": {
        "type": "boolean"
      },
      "shields": {
        "type": "array",
        "items": {
          "type": "string",
          "enum": [
            "block",
            "admin_notification"
          ]
        }
      },
      "allowlist": {
        "type": "array",
        "items": {
          "type": "string",
          "anyOf": [
            {
              "type": "string",
              "format": "ipv4"
            },
            {
              "type": "string",
              "format": "cidr"
            },
            {
              "type": "string",
              "format": "ipv6"
            },
            {
              "type": "string",
              "format": "ipv6_cidr"
            }
          ]
        },
        "maxItems": 100
      },
      "stage": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "pre-login": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "max_attempts": {
                "type": "integer",
                "default": 100,
                "minimum": 1,
                "maximum": 2500
              },
              "rate": {
                "type": "integer",
                "default": 864000,
                "minimum": 34560,
                "maximum": 86400000
              }
            }
          },
          "pre-user-registration": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "max_attempts": {
                "type": "integer",
                "default": 50,
                "minimum": 1,
                "maximum": 72000
              },
              "rate": {
                "type": "integer",
                "default": 1728000,
                "minimum": 1200,
                "maximum": 86400000
              }
            }
          },
          "pre-custom-token-exchange": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "max_attempts": {
                "type": "integer",
                "default": 10,
                "minimum": 1,
                "maximum": 2500
              },
              "rate": {
                "type": "integer",
                "default": 8640000,
                "minimum": 34560,
                "maximum": 86400000
              }
            }
          }
        }
      }
    }
  },
  "breached-password-detection": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "enabled": {
        "type": "boolean",
        "default": true
      },
      "shields": {
        "type": "array",
        "items": {
          "type": "string",
          "enum": [
            "block",
            "user_notification",
            "admin_notification"
          ]
        }
      },
      "admin_notification_frequency": {
        "type": "array",
        "items": {
          "type": "string",
          "enum": [
            "immediately",
            "daily",
            "weekly",
            "monthly"
          ]
        }
      },
      "method": {
        "type": "string",
        "default": "standard",
        "enum": [
          "standard",
          "enhanced"
        ]
      },
      "stage": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "pre-user-registration": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "shields": {
                "type": "array",
                "items": {
                  "type": "string",
                  "enum": [
                    "block",
                    "admin_notification"
                  ]
                }
              }
            }
          },
          "pre-change-password": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "shields": {
                "type": "array",
                "items": {
                  "type": "string",
                  "enum": [
                    "block",
                    "admin_notification"
                  ]
                }
              }
            }
          }
        }
      }
    }
  },
  "bot-detection": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "bot_detection_level": {
        "type": "string",
        "enum": [
          "low",
          "medium",
          "high"
        ]
      },
      "challenge_password_policy": {
        "type": "string",
        "enum": [
          "never",
          "when_risky",
          "always"
        ]
      },
      "challenge_passwordless_policy": {
        "type": "string",
        "enum": [
          "never",
          "when_risky",
          "always"
        ]
      },
      "challenge_password_reset_policy": {
        "type": "string",
        "enum": [
          "never",
          "when_risky",
          "always"
        ]
      },
      "allowlist": {
        "type": "array",
        "items": {
          "type": "string",
          "oneOf": [
            {
              "type": "string",
              "format": "ipv4"
            },
            {
              "type": "string",
              "format": "ipv6"
            },
            {
              "type": "string",
              "format": "cidr"
            },
            {
              "type": "string",
              "format": "ipv6_cidr"
            }
          ]
        }
      },
      "monitoring_mode_enabled": {
        "type": "boolean"
      }
    }
  },
  "captcha": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "active_provider_id": {
        "type": "string",
        "maxLength": 36,
        "enum": [
          "arkose",
          "auth_challenge",
          "friendly_captcha",
          "hcaptcha",
          "recaptcha_v2",
          "recaptcha_enterprise",
          "simple_captcha"
        ]
      },
      "arkose": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "site_key",
          "secret"
        ],
        "properties": {
          "site_key": {
            "type": "string",
            "maxLength": 100
          },
          "secret": {
            "type": "string",
            "maxLength": 100
          },
          "client_subdomain": {
            "type": "string",
            "maxLength": 100
          },
          "verify_subdomain": {
            "type": "string",
            "maxLength": 100
          },
          "fail_open": {
            "type": "boolean"
          }
        }
      },
      "auth_challenge": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "fail_open"
        ],
        "properties": {
          "fail_open": {
            "type": "boolean"
          }
        }
      },
      "hcaptcha": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "site_key",
          "secret"
        ],
        "properties": {
          "site_key": {
            "type": "string",
            "maxLength": 100
          },
          "secret": {
            "type": "string",
            "maxLength": 100
          }
        }
      },
      "friendly_captcha": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "site_key",
          "secret"
        ],
        "properties": {
          "site_key": {
            "type": "string",
            "maxLength": 100
          },
          "secret": {
            "type": "string",
            "maxLength": 100
          }
        }
      },
      "recaptcha_enterprise": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "site_key",
          "api_key",
          "project_id"
        ],
        "properties": {
          "site_key": {
            "type": "string",
            "maxLength": 100
          },
          "api_key": {
            "type": "string",
            "maxLength": 100
          },
          "project_id": {
            "type": "string",
            "maxLength": 100
          }
        }
      },
      "recaptcha_v2": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "site_key",
          "secret"
        ],
        "properties": {
          "site_key": {
            "type": "string",
            "maxLength": 100
          },
          "secret": {
            "type": "string",
            "maxLength": 100
          }
        }
      },
      "simple_captcha": {
        "type": "object",
        "additionalProperties": true
      }
    }
  }
}`
