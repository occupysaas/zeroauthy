// Frozen T1–T3 writable inventory, 2026-10-22. Runtime never reads observer documents.
package tenantrules

const inventory = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "change_password": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "type": "boolean",
          "default": false
        },
        "html": {
          "type": "string",
          "default": ""
        }
      }
    },
    "device_flow": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "charset": {
          "type": "string",
          "default": "base20",
          "enum": [
            "base20",
            "digits"
          ]
        },
        "mask": {
          "type": "string",
          "default": "****-****",
          "maxLength": 20
        }
      }
    },
    "guardian_mfa_page": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "enabled": {
          "type": "boolean",
          "default": false
        },
        "html": {
          "type": "string",
          "default": ""
        }
      }
    },
    "default_audience": {
      "type": "string",
      "default": ""
    },
    "default_directory": {
      "type": "string",
      "default": ""
    },
    "error_page": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "html": {
          "type": "string",
          "default": ""
        },
        "show_log_link": {
          "type": "boolean",
          "default": false
        },
        "url": {
          "type": "string",
          "default": "https://mycompany.org/error",
          "format": "absolute-uri-or-empty"
        }
      }
    },
    "default_token_quota": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "minProperties": 1,
      "properties": {
        "clients": {
          "type": "object",
          "additionalProperties": true,
          "required": [
            "client_credentials"
          ],
          "properties": {
            "client_credentials": {
              "type": "object",
              "additionalProperties": false,
              "minProperties": 1,
              "properties": {
                "enforce": {
                  "type": "boolean"
                },
                "per_day": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 2147483647
                },
                "per_hour": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 2147483647
                }
              }
            }
          }
        },
        "organizations": {
          "type": "object",
          "additionalProperties": true,
          "required": [
            "client_credentials"
          ],
          "properties": {
            "client_credentials": {
              "type": "object",
              "additionalProperties": false,
              "minProperties": 1,
              "properties": {
                "enforce": {
                  "type": "boolean"
                },
                "per_day": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 2147483647
                },
                "per_hour": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 2147483647
                }
              }
            }
          }
        }
      }
    },
    "flags": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "change_pwd_flow_v1": {
          "type": "boolean",
          "default": false
        },
        "enable_apis_section": {
          "type": "boolean",
          "default": false
        },
        "disable_impersonation": {
          "type": "boolean",
          "default": false,
          "readOnly": true
        },
        "enable_client_connections": {
          "type": "boolean",
          "default": true
        },
        "enable_pipeline2": {
          "type": "boolean",
          "default": true
        },
        "allow_legacy_delegation_grant_types": {
          "type": "boolean"
        },
        "allow_legacy_ro_grant_types": {
          "type": "boolean"
        },
        "allow_legacy_tokeninfo_endpoint": {
          "type": "boolean"
        },
        "enable_legacy_profile": {
          "type": "boolean"
        },
        "enable_idtoken_api2": {
          "type": "boolean"
        },
        "enable_public_signup_user_exists_error": {
          "type": "boolean"
        },
        "enable_sso": {
          "type": "boolean"
        },
        "allow_changing_enable_sso": {
          "type": "boolean"
        },
        "disable_clickjack_protection_headers": {
          "type": "boolean"
        },
        "no_disclose_enterprise_connections": {
          "type": "boolean"
        },
        "enforce_client_authentication_on_passwordless_start": {
          "type": "boolean"
        },
        "enable_adfs_waad_email_verification": {
          "type": "boolean"
        },
        "revoke_refresh_token_grant": {
          "type": "boolean"
        },
        "dashboard_log_streams_next": {
          "type": "boolean"
        },
        "dashboard_insights_view": {
          "type": "boolean"
        },
        "disable_fields_map_fix": {
          "type": "boolean"
        },
        "mfa_show_factor_list_on_enrollment": {
          "type": "boolean"
        },
        "remove_alg_from_jwks": {
          "type": "boolean"
        },
        "improved_signup_bot_detection_in_classic": {
          "type": "boolean"
        },
        "genai_trial": {
          "type": "boolean"
        },
        "local_resource_discovery": {
          "type": "boolean"
        },
        "enable_dynamic_client_registration": {
          "type": "boolean",
          "default": false
        },
        "disable_management_api_sms_obfuscation": {
          "type": "boolean",
          "default": true
        },
        "trust_azure_adfs_email_verified_connection_property": {
          "type": "boolean",
          "default": false
        },
        "custom_domains_provisioning": {
          "type": "boolean",
          "default": false
        }
      }
    },
    "friendly_name": {
      "type": "string",
      "default": "My Company"
    },
    "picture_url": {
      "type": "string",
      "default": "https://mycompany.org/logo.png",
      "format": "absolute-uri-or-empty"
    },
    "support_email": {
      "type": "string",
      "default": "support@mycompany.org",
      "format": "email-or-empty"
    },
    "support_url": {
      "type": "string",
      "default": "https://mycompany.org/support",
      "format": "absolute-uri-or-empty"
    },
    "allowed_logout_urls": {
      "type": "array",
      "items": {
        "type": "string",
        "format": "url-with-placeholders"
      }
    },
    "session_lifetime": {
      "type": "integer",
      "default": 168,
      "minimum": 1
    },
    "session_lifetime_in_minutes": {
      "type": "integer",
      "minimum": 1
    },
    "idle_session_lifetime": {
      "type": "integer",
      "default": 72,
      "minimum": 1
    },
    "idle_session_lifetime_in_minutes": {
      "type": "integer",
      "minimum": 1
    },
    "ephemeral_session_lifetime": {
      "type": "integer",
      "default": 72,
      "minimum": 1
    },
    "idle_ephemeral_session_lifetime": {
      "type": "integer",
      "default": 24,
      "minimum": 1
    },
    "ephemeral_session_lifetime_in_minutes": {
      "type": "integer",
      "minimum": 1
    },
    "idle_ephemeral_session_lifetime_in_minutes": {
      "type": "integer",
      "minimum": 1
    },
    "sandbox_version": {
      "type": "string",
      "default": "22",
      "maxLength": 8
    },
    "legacy_sandbox_version": {
      "type": "string",
      "maxLength": 8
    },
    "default_redirection_uri": {
      "type": "string",
      "format": "absolute-https-uri-or-empty"
    },
    "enabled_locales": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string",
        "enum": [
          "am",
          "ar",
          "ar-EG",
          "ar-SA",
          "az",
          "bg",
          "bn",
          "bs",
          "ca-ES",
          "cnr",
          "cs",
          "cy",
          "da",
          "de",
          "el",
          "en",
          "en-CA",
          "es",
          "es-419",
          "es-AR",
          "es-MX",
          "et",
          "eu-ES",
          "fa",
          "fi",
          "fr",
          "fr-CA",
          "fr-FR",
          "gl-ES",
          "gu",
          "he",
          "hi",
          "hr",
          "hu",
          "hy",
          "id",
          "is",
          "it",
          "ja",
          "ka",
          "kk",
          "kn",
          "ko",
          "lt",
          "lv",
          "mk",
          "ml",
          "mn",
          "mr",
          "ms",
          "my",
          "nb",
          "nl",
          "nn",
          "no",
          "pa",
          "pl",
          "pt",
          "pt-BR",
          "pt-PT",
          "ro",
          "ru",
          "sk",
          "sl",
          "so",
          "sq",
          "sr",
          "sv",
          "sw",
          "ta",
          "te",
          "th",
          "tl",
          "tr",
          "uk",
          "ur",
          "vi",
          "zgh",
          "zh-CN",
          "zh-HK",
          "zh-MO",
          "zh-TW"
        ]
      }
    },
    "access_token": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "claims_mapping": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "custom_claims": {
              "type": "array",
              "items": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "name",
                  "expression"
                ],
                "properties": {
                  "name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255
                  },
                  "expression": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "pattern": "^[A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*(?:\\.[A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)+$"
                  }
                }
              }
            }
          }
        }
      }
    },
    "security_headers": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "content_security_policy": {
          "type": [
            "object",
            "null"
          ],
          "additionalProperties": false,
          "properties": {
            "enabled": {
              "type": "boolean"
            },
            "policies": {
              "type": "array",
              "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                  "mode": {
                    "type": "string",
                    "enum": [
                      "enforcing",
                      "reporting"
                    ]
                  },
                  "directives": {
                    "type": "object",
                    "additionalProperties": {
                      "type": "array"
                    },
                    "maxProperties": 30
                  },
                  "flags": {
                    "type": "array",
                    "items": {
                      "type": "string",
                      "enum": [
                        "upgrade-insecure-requests",
                        "block-all-mixed-content"
                      ]
                    }
                  },
                  "reporting": {
                    "type": [
                      "object",
                      "null"
                    ],
                    "additionalProperties": false,
                    "properties": {
                      "report_uri": {
                        "type": "string"
                      },
                      "report_to_group": {
                        "type": "string"
                      }
                    }
                  }
                }
              }
            },
            "reporting_infrastructure": {
              "type": [
                "object",
                "null"
              ],
              "additionalProperties": false,
              "properties": {
                "report_to": {
                  "type": [
                    "object",
                    "null"
                  ],
                  "additionalProperties": false,
                  "properties": {
                    "group": {
                      "type": "string"
                    },
                    "max_age": {
                      "type": "integer"
                    },
                    "endpoints": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                          "url": {
                            "type": "string"
                          }
                        }
                      }
                    }
                  }
                },
                "reporting_endpoints": {
                  "type": "object",
                  "additionalProperties": {
                    "type": "string"
                  }
                }
              }
            }
          }
        },
        "x_xss_protection": {
          "type": [
            "object",
            "null"
          ],
          "additionalProperties": false,
          "properties": {
            "enabled": {
              "type": "boolean"
            },
            "mode": {
              "type": "string",
              "enum": [
                "block"
              ]
            },
            "report_uri": {
              "type": "string"
            }
          }
        }
      }
    },
    "session_cookie": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "required": [
        "mode"
      ],
      "properties": {
        "mode": {
          "type": "string",
          "default": "persistent",
          "enum": [
            "persistent",
            "non-persistent"
          ]
        }
      }
    },
    "sessions": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "oidc_logout_prompt_enabled": {
          "type": "boolean",
          "default": true
        },
        "anonymous": {
          "type": [
            "object",
            "null"
          ],
          "additionalProperties": false,
          "properties": {
            "lifetime_in_minutes": {
              "type": "integer",
              "default": 43200,
              "minimum": 1,
              "maximum": 525600
            },
            "activate_cookie": {
              "type": "boolean",
              "default": true
            }
          }
        }
      }
    },
    "oidc_logout": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "rp_logout_end_session_endpoint_discovery": {
          "type": "boolean",
          "default": true
        }
      }
    },
    "customize_mfa_in_postlogin_action": {
      "type": [
        "boolean",
        "null"
      ],
      "default": false
    },
    "allow_organization_name_in_authentication_api": {
      "type": [
        "boolean",
        "null"
      ],
      "default": false
    },
    "acr_values_supported": {
      "type": [
        "array",
        "null"
      ],
      "minItems": 0,
      "items": {
        "type": "string",
        "format": "acr"
      }
    },
    "mtls": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "enable_endpoint_aliases": {
          "type": "boolean",
          "default": false
        }
      }
    },
    "pushed_authorization_requests_supported": {
      "type": [
        "boolean",
        "null"
      ],
      "default": false
    },
    "authorization_response_iss_parameter_supported": {
      "type": [
        "boolean",
        "null"
      ],
      "default": false
    },
    "dpop_strict_refresh_token_binding": {
      "type": [
        "boolean",
        "null"
      ],
      "default": false
    },
    "skip_non_verifiable_callback_uri_confirmation_prompt": {
      "type": [
        "boolean",
        "null"
      ]
    },
    "resource_parameter_profile": {
      "type": "string",
      "default": "audience",
      "enum": [
        "audience",
        "compatibility"
      ]
    },
    "client_id_metadata_document_supported": {
      "type": "boolean",
      "default": false
    },
    "client_id_metadata_document_dynamic_registration_supported": {
      "type": "boolean",
      "default": false
    },
    "enable_ai_guide": {
      "type": "boolean"
    },
    "phone_consolidated_experience": {
      "type": "boolean"
    },
    "include_session_metadata_in_tenant_logs": {
      "type": "boolean",
      "default": false
    },
    "dynamic_client_registration_security_mode": {
      "type": "string",
      "enum": [
        "strict",
        "permissive"
      ]
    },
    "country_codes": {
      "type": [
        "object",
        "null"
      ],
      "additionalProperties": false,
      "properties": {
        "list": {
          "type": "array",
          "items": {
            "type": "string",
            "minLength": 2,
            "maxLength": 2,
            "pattern": "^[A-Z]{2}$"
          }
        },
        "mode": {
          "type": "string",
          "enum": [
            "allow",
            "deny"
          ]
        }
      }
    }
  },
  "minProperties": 1
}`
