# Elastic Stack 8.x com Segurança - Guia Completo

Este guia documenta a configuração completa do Elastic Stack 8.x (Elasticsearch, Logstash, Kibana) com Filebeat, incluindo autenticação e controle de acesso.

## 📋 Pré-requisitos

- Docker e Docker Compose
- Sistema Linux (testado no Ubuntu/CentOS)
- Mínimo 4GB RAM disponível
- Portas livres: 9200, 5601, 5044

## 🏗️ Arquitetura

```
Filebeat → Logstash (porta 5044) → Elasticsearch (porta 9200) → Kibana (porta 5601)
```

## 🚀 Configuração Passo a Passo

### 1. Docker Compose (docker-compose.yml)

```yaml
version: '3.7'

networks:
  elastic:
    driver: overlay

volumes:
  elasticsearch-data:
    driver: local
  elasticsearch-certs:
    driver: local

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.enrollment.enabled=true
      - ELASTIC_PASSWORD=ElasticPassword123!
      - xpack.security.http.ssl.enabled=false
      - xpack.security.transport.ssl.enabled=false
    ports:
      - target: 9200
        published: 9200
        protocol: tcp
        mode: host
    networks:
      - elastic
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
      - elasticsearch-certs:/usr/share/elasticsearch/config/certs
    deploy:
      placement:
        constraints:
          - node.hostname == srv22
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 2G
    ulimits:
      memlock:
        soft: -1
        hard: -1

  logstash:
    image: docker.elastic.co/logstash/logstash:8.15.0
    environment:
      - xpack.monitoring.enabled=false
      - "LS_JAVA_OPTS=-Xmx1g -Xms1g"
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=logstash_writer
      - ELASTICSEARCH_PASSWORD=LogstashWriter123!
    volumes:
      - /home/pathfind/elastic-poc/logstash/pipeline:/usr/share/logstash/pipeline/
    ports:
      - target: 5044
        published: 5044
        protocol: tcp
        mode: host
    networks:
      - elastic
    depends_on:
      - elasticsearch
    deploy:
      placement:
        constraints:
          - node.hostname == srv22
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M

  kibana:
    image: docker.elastic.co/kibana/kibana:8.15.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=KibanaPassword123!
      - SERVER_HOST=0.0.0.0
      - SERVER_PUBLICBASEURL=http://192.168.25.22:5601
    ports:
      - target: 5601
        published: 5601
        protocol: tcp
        mode: host
    networks:
      - elastic
    depends_on:
      - elasticsearch
    deploy:
      placement:
        constraints:
          - node.hostname == srv22
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M
```

### 2. Configuração do Logstash (logstash/pipeline/logstash.conf)

```properties
input {
  beats {
    port => 5044
  }
}

filter {
  # Identificar tipo de log baseado no nome do arquivo
  if [log][file][path] =~ "catalina" {
    mutate { add_field => { "log_type" => "catalina" } }
    
    # Parse de logs do Catalina - versões diferentes
    grok {
      match => { 
        "message" => [
          "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} \[%{DATA:thread}\] %{DATA:class} - %{GREEDYDATA:log_message}",
          "%{DATA:date} %{TIME:time} %{LOGLEVEL:level} \[%{DATA:thread}\] %{DATA:class} - %{GREEDYDATA:log_message}",
          "%{GREEDYDATA:log_message}"
        ]
      }
    }
  }
  
  else if [log][file][path] =~ "localhost" {
    mutate { add_field => { "log_type" => "localhost" } }
    
    # Parse de access logs
    grok {
      match => { 
        "message" => [
          "%{COMBINEDAPACHELOG}",
          "%{COMMONAPACHELOG}",
          "%{GREEDYDATA:log_message}"
        ]
      }
    }
  }
  
  else if [log][file][path] =~ "manager" {
    mutate { add_field => { "log_type" => "manager" } }
    
    # Tentar parse básico para manager
    grok {
      match => { 
        "message" => [
          "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:log_message}",
          "%{GREEDYDATA:log_message}"
        ]
      }
    }
  }
  
  else if [log][file][path] =~ "host-manager" {
    mutate { add_field => { "log_type" => "host-manager" } }
    
    # Tentar parse básico para host-manager
    grok {
      match => { 
        "message" => [
          "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:log_message}",
          "%{GREEDYDATA:log_message}"
        ]
      }
    }
  }
  
  else if [log][file][path] =~ "apache2|httpd|access\.log|error\.log" {
    mutate { add_field => { "log_type" => "redir" } }
    
    # Parse para logs do Apache
    if [log][file][path] =~ "access" {
      grok {
        match => { 
          "message" => [
            "%{COMBINEDAPACHELOG}",
            "%{COMMONAPACHELOG}",
            "%{GREEDYDATA:log_message}"
          ]
        }
      }
    }
    else if [log][file][path] =~ "error" {
      grok {
        match => { 
          "message" => [
            "\[%{HTTPDATE:timestamp}\] \[%{LOGLEVEL:level}\] \[pid %{NUMBER:pid}\] %{GREEDYDATA:log_message}",
            "\[%{HTTPDATE:timestamp}\] \[%{DATA:module}:%{LOGLEVEL:level}\] \[pid %{NUMBER:pid}\] %{GREEDYDATA:log_message}",
            "%{GREEDYDATA:log_message}"
          ]
        }
      }
    }
  }

  # Converter timestamp se existir
  if [timestamp] {
    date {
      match => [ "timestamp", "yyyy-MM-dd HH:mm:ss,SSS", "ISO8601", "dd-MMM-yyyy HH:mm:ss.SSS", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
  }

  # Criar campo level genérico se não existir
  if ![level] {
    if [message] =~ /ERROR|error/ {
      mutate { add_field => { "level" => "ERROR" } }
    }
    else if [message] =~ /WARN|warn|WARNING/ {
      mutate { add_field => { "level" => "WARN" } }
    }
    else if [message] =~ /INFO|info/ {
      mutate { add_field => { "level" => "INFO" } }
    }
    else if [message] =~ /DEBUG|debug/ {
      mutate { add_field => { "level" => "DEBUG" } }
    }
    else {
      mutate { add_field => { "level" => "UNKNOWN" } }
    }
  }

  # Manter apenas o hostname, remover resto do objeto host
  mutate {
    add_field => { "hostname" => "%{[host][name]}" }
    remove_field => [ "[host]", "[agent]", "[ecs]", "[input]", "[log][offset]" ]
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "springboot-logs-%{+YYYY.MM.dd}"
    user => "logstash_writer"
    password => "LogstashWriter123!"
    ssl_enabled => false
  }
}
```

### 3. Configuração do Filebeat (filebeat-v8.yml)

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/lib/docker/volumes/motor-simulacao_ptfses-j17/_data/*
  fields:
    service: ptfses
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/lib/docker/volumes/motor-simulacao_plnses-j17/_data/*
  fields:
    service: plnses
  fields_under_root: true

# ===== Elasticsearch output (COMENTADO para usar Logstash) =====
#output.elasticsearch:
#  hosts: ["localhost:9200"]
#  username: "elastic"
#  password: "ElasticPassword123!"

# ===== Logstash output =====
output.logstash:
  hosts: ["localhost:5044"]

# ===== Kibana setup =====
setup.kibana:
  host: "localhost:5601"
  username: "elastic"
  password: "ElasticPassword123!"

# ===== Logging configuration =====
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
```

## 🔧 Processo de Inicialização

### 1. Subir o Elasticsearch primeiro

```bash
docker-compose up -d elasticsearch
```

### 2. Aguardar inicialização (2-3 minutos)

```bash
# Verificar se está respondendo
curl -u elastic:ElasticPassword123! http://localhost:9200/_cluster/health
```

### 3. Configurar usuários de segurança

```bash
# Entrar no container do Elasticsearch
docker exec -it ELASTICSEARCH_CONTAINER /bin/bash

# Resetar senhas dos usuários built-in
./bin/elasticsearch-reset-password -u kibana_system
./bin/elasticsearch-reset-password -u logstash_system
```

### 4. Criar usuário personalizado para Logstash

No Kibana Dev Tools (http://localhost:5601):

```json
# Criar role personalizada
PUT /_security/role/logstash_writer
{
  "cluster": ["monitor", "manage_index_templates", "manage_ilm"],
  "indices": [
    {
      "names": ["springboot-logs-*"],
      "privileges": ["create_index", "write", "create", "index", "manage"]
    }
  ]
}

# Criar usuário
POST /_security/user/logstash_writer
{
  "password": "LogstashWriter123!",
  "roles": ["logstash_writer"]
}
```

### 5. Atualizar senhas no docker-compose

Atualize as senhas geradas no arquivo docker-compose.yml:

```yaml
kibana:
  environment:
    - ELASTICSEARCH_PASSWORD=SENHA_GERADA_KIBANA_SYSTEM
```

### 6. Subir resto da stack

```bash
docker-compose up -d
```

### 7. Configurar Filebeat

```bash
# Copiar configuração
sudo cp filebeat-v8.yml /etc/filebeat/filebeat.yml

# Testar configuração
sudo filebeat test config

# Iniciar serviço
sudo systemctl start filebeat
sudo systemctl enable filebeat
```

## 🔍 Verificações e Testes

### 1. Verificar saúde do cluster

```bash
curl -u elastic:ElasticPassword123! http://localhost:9200/_cluster/health?pretty
```

### 2. Testar conectividade do Filebeat

```bash
sudo filebeat test output
```

### 3. Criar log de teste

```bash
echo "$(date) INFO [test] Test log from application" >> /var/lib/docker/volumes/motor-simulacao_ptfses-j17/_data/test.log
```

### 4. Verificar índices no Elasticsearch

No Kibana Dev Tools:

```json
GET _cat/indices/springboot-logs-*
```

### 5. Criar Data View no Kibana

1. Login no Kibana: http://localhost:5601
   - Usuário: `elastic`
   - Senha: `ElasticPassword123!`

2. Stack Management → Kibana → Data Views → Create data view
   - Name: `Springboot Logs`
   - Index pattern: `springboot-logs-*`
   - Timestamp field: `@timestamp`

3. Discover → Selecionar "Springboot Logs"

## 🛠️ Troubleshooting

### Problemas Comuns

#### 1. Erro 401 no Logstash
**Causa:** Credenciais incorretas ou usuário sem permissões  
**Solução:** Verificar usuário `logstash_writer` e suas permissões

#### 2. Filebeat não envia dados
**Causa:** Dois outputs configurados ou paths incorretos  
**Solução:** Comentar `output.elasticsearch` e verificar paths dos volumes

#### 3. Kibana não conecta
**Causa:** Senha do `kibana_system` incorreta  
**Solução:** Resetar senha e atualizar docker-compose

#### 4. Índices não aparecem
**Causa:** Pipeline não está funcionando  
**Solução:** Verificar logs do Logstash e Filebeat

### Logs para Debug

```bash
# Logs do Elasticsearch
docker logs ELASTICSEARCH_CONTAINER

# Logs do Logstash
docker service logs STACK_logstash --tail 50

# Logs do Kibana
docker logs KIBANA_CONTAINER

# Logs do Filebeat
sudo tail -f /var/log/filebeat/filebeat.log
```

## 🔒 Segurança

### Usuários Configurados

- **elastic**: Super usuário (todas as permissões)
- **kibana_system**: Usuário interno do Kibana
- **logstash_writer**: Usuário personalizado para escrita de dados

### Portas Expostas

- **9200**: Elasticsearch (com autenticação)
- **5601**: Kibana (com autenticação)
- **5044**: Logstash Beats input (sem autenticação - considere firewall)

### Recomendações de Segurança

1. **Firewall**: Restringir acesso à porta 5044 apenas para IPs dos Filebeats
2. **SSL/TLS**: Habilitar SSL em produção
3. **Senhas fortes**: Alterar senhas padrão
4. **Backups**: Configurar backup dos dados do Elasticsearch

## 📊 Campos Processados

### Campos Automaticamente Criados

- `@timestamp`: Timestamp do evento
- `hostname`: Nome do host de origem
- `service`: Identificação do serviço (ptfses/plnses)
- `log_type`: Tipo do log (catalina/localhost/manager/host-manager/redir)
- `level`: Nível do log (INFO/WARN/ERROR/DEBUG/UNKNOWN)
- `log_message`: Mensagem processada do log

### Filtros Grok Configurados

- **Catalina**: Logs do Tomcat/Spring Boot
- **Localhost**: Access logs HTTP
- **Manager/Host-Manager**: Logs de management do Tomcat
- **Apache**: Access e error logs do Apache HTTP Server

## 📈 Monitoramento

### Dashboards Recomendados

1. **Log Levels por Tempo**: Visualização de erros vs warnings vs info
2. **Serviços por Volume**: Quantidade de logs por serviço
3. **Top Errors**: Principais mensagens de erro
4. **Timeline**: Distribuição temporal dos logs

### Alertas Sugeridos

- Alto volume de logs ERROR
- Falta de logs de um serviço específico
- Picos anômalos de volume de logs

## � Gerenciamento de Usuários e Perfis de Acesso

### Conceitos de Segurança

O Elastic Stack 8.x usa uma estrutura hierárquica para controle de acesso:
```
Usuários → Roles → Privilégios → Recursos
```

### Criar Roles (Perfis) Personalizadas

#### 1. Via Kibana Interface
- **Stack Management** → **Security** → **Roles** → **Create role**

#### 2. Via Dev Tools

**Desenvolvedor (Somente Leitura):**
```json
PUT /_security/role/dev_role
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["springboot-logs-*", "dev-*"],
      "privileges": ["read", "view_index_metadata"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": ["feature_discover.read", "feature_visualize.read", "feature_dashboard.read"],
      "resources": ["*"]
    }
  ]
}
```

**QA/Tester (Leitura + Dashboards):**
```json
PUT /_security/role/qa_role
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["springboot-logs-*", "qa-*", "test-*"],
      "privileges": ["read", "view_index_metadata"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": [
        "feature_discover.read",
        "feature_visualize.all",
        "feature_dashboard.all",
        "feature_savedObjectsManagement.read"
      ],
      "resources": ["*"]
    }
  ]
}
```

**Administrador de Logs:**
```json
PUT /_security/role/log_admin_role
{
  "cluster": ["monitor", "manage_index_templates"],
  "indices": [
    {
      "names": ["*-logs-*", "logstash-*"],
      "privileges": ["all"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": ["all"],
      "resources": ["*"]
    }
  ]
}
```

**Visualizador Executivo (Somente Dashboards):**
```json
PUT /_security/role/executive_role
{
  "cluster": [],
  "indices": [
    {
      "names": ["springboot-logs-*"],
      "privileges": ["read"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": ["feature_dashboard.read"],
      "resources": ["*"]
    }
  ]
}
```

### Criar Usuários

#### Via Dev Tools:

**Usuário Desenvolvedor:**
```json
POST /_security/user/dev_user
{
  "password": "DevPassword123!",
  "roles": ["dev_role"],
  "full_name": "Desenvolvedor Sistema",
  "email": "dev@empresa.com"
}
```

**Usuário QA:**
```json
POST /_security/user/qa_user
{
  "password": "QaPassword123!",
  "roles": ["qa_role"],
  "full_name": "Analista QA",
  "email": "qa@empresa.com"
}
```

**Usuário Admin de Logs:**
```json
POST /_security/user/log_admin
{
  "password": "LogAdminPassword123!",
  "roles": ["log_admin_role"],
  "full_name": "Administrador de Logs",
  "email": "logadmin@empresa.com"
}
```

**Usuário Executivo:**
```json
POST /_security/user/executive_user
{
  "password": "ExecPassword123!",
  "roles": ["executive_role"],
  "full_name": "Diretor Executivo",
  "email": "diretor@empresa.com"
}
```

#### Via Interface Web:
1. **Stack Management** → **Security** → **Users** → **Create user**
2. Preencher dados do usuário
3. Selecionar roles apropriadas

### Spaces (Espaços) para Segregação

#### Criar Spaces:
- **Stack Management** → **Kibana** → **Spaces** → **Create space**

**Exemplos de Spaces:**
- **desenvolvimento** (`/s/desenvolvimento`) - Para desenvolvedores
- **qa** (`/s/qa`) - Para testes
- **executivo** (`/s/executivo`) - Dashboards executivos
- **producao** (`/s/producao`) - Ambiente produtivo

#### Associar Roles aos Spaces:
```json
PUT /_security/role/dev_space_role
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["dev-*", "springboot-logs-*"],
      "privileges": ["read"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": ["feature_discover.read", "feature_dashboard.read"],
      "resources": ["space:desenvolvimento"]
    }
  ]
}
```

### Roles por Departamento

**Suporte Nível 1 (Somente Leitura):**
```json
PUT /_security/role/support_l1_role
{
  "cluster": [],
  "indices": [
    {
      "names": ["springboot-logs-*"],
      "privileges": ["read"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": ["feature_discover.read", "feature_dashboard.read"],
      "resources": ["*"]
    }
  ]
}
```

**Analista de Dados:**
```json
PUT /_security/role/analyst_role
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["springboot-logs-*", "metrics-*"],
      "privileges": ["read", "view_index_metadata"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": [
        "feature_discover.all",
        "feature_visualize.all",
        "feature_dashboard.all",
        "feature_canvas.read"
      ],
      "resources": ["*"]
    }
  ]
}
```

### Principais Privilégios Kibana

**Features Disponíveis:**
- `feature_discover`: Pesquisa e exploração de logs
- `feature_dashboard`: Visualização de dashboards
- `feature_visualize`: Criação de visualizações
- `feature_canvas`: Apresentações e relatórios
- `feature_maps`: Mapas geográficos
- `feature_ml`: Machine Learning
- `feature_apm`: Monitoramento de Performance
- `feature_uptime`: Monitoramento de disponibilidade
- `feature_logs`: Interface de logs
- `feature_infrastructure`: Monitoramento de infraestrutura

**Níveis de Acesso:**
- `.read`: Somente leitura
- `.all`: Leitura e escrita completas

### Alterar Senhas de Usuários

**Alterar senha de um usuário específico:**
```json
POST /_security/user/{nome_do_usuario}/_password
{
  "password": "nova_senha_aqui"
}
```

**Exemplos práticos:**
```json
# Alterar senha do dev_user
POST /_security/user/dev_user/_password
{
  "password": "NovaDevPassword123!"
}

# Alterar senha do usuário kibana_system
POST /_security/user/kibana_system/_password
{
  "password": "NovaKibanaPassword123!"
}

# Alterar sua própria senha
POST /_security/user/_password
{
  "password": "MinhaNovaSenha123!"
}
```

**⚠️ Após alterar senhas, atualizar:**
- `docker-compose.yml` (environment variables)
- `logstash.conf` (output credentials)
- Reiniciar serviços afetados

### Validar Permissões

**Verificar usuário:**
```json
GET /_security/user/dev_user
```

**Testar privilégios:**
```json
GET /_security/user/_privileges
```

**Verificar autenticação atual:**
```json
GET /_security/_authenticate
```

**Testar conectividade:**
```bash
curl -u dev_user:DevPassword123! http://localhost:9200/_cluster/health
```

### Boas Práticas de Segurança

1. **Princípio do menor privilégio**: Conceder apenas acessos necessários
2. **Usar Spaces**: Segregar ambientes por área/projeto
3. **Rotação de senhas**: Alterar senhas periodicamente
4. **Audit logs**: Monitorar acessos e ações dos usuários
5. **Backup de configuração**: Exportar roles e usuários regularmente
6. **Senhas fortes**: Usar políticas de senha robustas
7. **Revisão periódica**: Auditar permissões regularmente

## �🚀 Próximos Passos

1. **Configurar SSL/TLS** para comunicação segura
2. **Implementar ILM** (Index Lifecycle Management) para rotação de índices
3. **Adicionar mais filtros** para outros tipos de aplicação
4. **Configurar alertas** no Kibana
5. **Implementar backup** automatizado
6. **Configurar audit logs** para monitoramento de segurança
7. **Implementar SSO** (Single Sign-On) se necessário

---

**Versão**: 1.1  
**Atualizado**: Novembro 2025  
**Testado com**: Elastic Stack 8.15.0