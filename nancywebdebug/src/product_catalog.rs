use crate::{Confidence, EndpointScan, PortState, ProductLayer, ServiceKind, TransportProtocol};

pub(crate) fn canonical_product_name(name: &str) -> &str {
    if let Some(name) = crate::web_server::canonical_product_name(name) {
        return name;
    }
    match name.trim().to_ascii_lowercase().as_str() {
        "docker" | "docker engine" => "Docker Engine",
        "kubernetes" | "kubernetes api" => "Kubernetes",
        "openssh" => "OpenSSH",
        "dropbear" => "Dropbear",
        "mariadb" => "MariaDB",
        "mysql" => "MySQL",
        "redis" => "Redis",
        "valkey" => "Valkey",
        "opensearch" => "OpenSearch",
        "mongodb" => "MongoDB",
        "rabbitmq" => "RabbitMQ",
        "prometheus" => "Prometheus",
        "java" | "jvm" => "JVM",
        "dotnet" | ".net" => ".NET",
        "nodejs" | "node.js" => "Node.js",
        "apache zookeeper" => "ZooKeeper",
        "apache cassandra" => "Cassandra",
        _ => name.trim(),
    }
}

pub(crate) fn inventory_product_name(name: &str) -> Option<&str> {
    let name = name.trim();
    let name = canonical_product_name(name);
    match name.to_ascii_lowercase().as_str() {
        ""
        | "unknown"
        | "http"
        | "https"
        | "http/2"
        | "http/3"
        | "tls"
        | "ssl"
        | "tcp"
        | "udp"
        | "ssh"
        | "ftp"
        | "smtp"
        | "pop3"
        | "imap"
        | "rdp"
        | "vnc"
        | "rfb"
        | "ajp"
        | "iso-on-tcp"
        | "modbus"
        | "modbus/tcp"
        | "iec 60870-5-104"
        | "opc ua"
        | "omron fins"
        | "omron fins/tcp"
        | "ethernet/ip"
        | "ldap"
        | "smb"
        | "mqtt"
        | "amqp"
        | "rtsp"
        | "rtmp"
        | "dns"
        | "ntp"
        | "ike"
        | "quic"
        | "mqtt-sn"
        | "ssdp"
        | "stun"
        | "ws-discovery"
        | "sip"
        | "mdns"
        | "coap"
        | "srt"
        | "websocket"
        | "websockets"
        | "nfs"
        | "tftp"
        | "netbios"
        | "netbios name service"
        | "snmp"
        | "rtp"
        | "rtcp"
        | "dtls"
        | "telnet"
        | "bgp"
        | "pptp"
        | "dnp3"
        | "x11" => None,
        _ if name.to_ascii_lowercase().ends_with(" protocol") => None,
        _ => Some(name),
    }
}

pub(crate) fn associated_port(product: &str) -> Option<u16> {
    match canonical_product_name(product) {
        "RabbitMQ" => Some(15672),
        "Prometheus" => Some(9090),
        "MongoDB" => Some(27017),
        _ => None,
    }
}

pub(crate) fn reconcile(endpoint: &mut EndpointScan) {
    let products = std::mem::take(&mut endpoint.products);
    for mut product in products {
        if product.evidence.is_empty() {
            product.name = canonical_product_name(&product.name).to_owned();
            endpoint.products.push(product);
            continue;
        }
        for evidence in product.evidence {
            crate::exposure::add_product(
                endpoint,
                &product.name,
                product.layer,
                product.version.clone(),
                product.confidence,
                evidence,
            );
        }
    }
    let confirmed = endpoint
        .products
        .iter()
        .filter(|p| p.confidence >= Confidence::Medium)
        .map(|p| p.name.clone())
        .collect::<Vec<_>>();
    let specific = endpoint.products.iter().any(|p| {
        p.confidence >= Confidence::Medium
            && matches!(p.layer, ProductLayer::Server | ProductLayer::Protocol)
    });
    endpoint.products.retain(|p| {
        !(specific
            && p.confidence < Confidence::Medium
            && p.evidence.iter().all(|e| {
                e.starts_with("Open port association only;")
                    || e.starts_with("Service response suggests this product;")
            }))
    });
    endpoint.products.retain(|p| {
        !(p.confidence < Confidence::Medium
            && confirmed.iter().any(|name| {
                matches!(
                    (p.name.as_str(), name.as_str()),
                    ("MySQL", "MariaDB") | ("Redis", "Valkey") | ("Elasticsearch", "OpenSearch")
                )
            }))
    });
    ({
        let (endpoint,): (&mut EndpointScan,) = (endpoint,);
        'inlined_record_possible_products: {
            if endpoint.state != PortState::Open {
                break 'inlined_record_possible_products;
            }
            let service_product = match endpoint.service {
                ServiceKind::Mysql => Some("MySQL"),
                ServiceKind::PostgreSql => Some("PostgreSQL"),
                ServiceKind::Redis => Some("Redis"),
                ServiceKind::Rsync => Some("rsync"),
                ServiceKind::Memcached => Some("Memcached"),
                ServiceKind::ZooKeeper => Some("ZooKeeper"),
                ServiceKind::Cassandra => Some("Cassandra"),
                ServiceKind::ErlangEpmd => Some("Erlang EPMD"),
                ServiceKind::Git => Some("Git daemon"),
                ServiceKind::MongoDb => Some("MongoDB"),
                ServiceKind::Rpcbind => Some("rpcbind"),
                _ => None,
            };
            let candidate = service_product.or_else(|| {
                (endpoint.transport == TransportProtocol::Tcp
                    && matches!(
                        endpoint.service,
                        ServiceKind::Unknown
                            | ServiceKind::Http
                            | ServiceKind::Https
                            | ServiceKind::Tls
                    ))
                .then(|| {
                    let (port,): (u16,) = (endpoint.port,);
                    {
                        'inlined_possible_port_product: {
                            Some(match port {
                                111 => "rpcbind",
                                873 => "rsync",
                                1099 => "JVM",
                                1194 => "OpenVPN",
                                1433 => "Microsoft SQL Server",
                                1521 => "Oracle Database",
                                2181 => "ZooKeeper",
                                2375 | 2376 => "Docker",
                                2379 | 2380 => "etcd",
                                3306 => "MySQL",
                                4369 => "Erlang EPMD",
                                4786 => "Cisco Smart Install",
                                5432 => "PostgreSQL",
                                5601 => "Kibana",
                                5938 => "TeamViewer",
                                5984 => "CouchDB",
                                5985 | 5986 => "WinRM",
                                6379 => "Redis",
                                6443 => "Kubernetes",
                                7070 => "AnyDesk",
                                8086 => "InfluxDB",
                                8089 => "Splunk",
                                8291 => "MikroTik WinBox",
                                8500 => "Consul",
                                9001 => "Supervisor",
                                9090 => "Prometheus",
                                9042 => "Cassandra",
                                9200 | 9300 => "Elasticsearch",
                                9418 => "Git daemon",
                                10000 => "Webmin",
                                10050 => "Zabbix agent",
                                10051 => "Zabbix server",
                                10250 | 10255 => "Kubelet",
                                11211 => "Memcached",
                                15672 => "RabbitMQ",
                                25672 => "Erlang",
                                27017 => "MongoDB",
                                50000 => "IBM Db2",
                                _ => break 'inlined_possible_port_product None,
                            })
                        }
                    }
                })
                .flatten()
            });
            let Some(name) = candidate else {
                break 'inlined_record_possible_products;
            };
            if endpoint.products.iter().any(|p| {
                p.confidence >= Confidence::Medium
                    && (canonical_product_name(&p.name) == canonical_product_name(name)
                        || matches!(p.layer, ProductLayer::Server | ProductLayer::Protocol))
            }) {
                break 'inlined_record_possible_products;
            }
            if endpoint
                .products
                .iter()
                .any(|p| canonical_product_name(&p.name) == canonical_product_name(name))
            {
                break 'inlined_record_possible_products;
            }
            endpoint.products.push(crate::ProductDetection {
        name: canonical_product_name(name).to_owned(),
        layer: ProductLayer::Protocol,
        version: None,
        confidence: Confidence::Low,
        evidence: vec![if service_product.is_some() {
            "Service response suggests this product; implementation identity was not confirmed."
                .to_owned()
        } else {
            "Open port association only; product identity was not confirmed.".to_owned()
        }],
    });
        }
    });
}
