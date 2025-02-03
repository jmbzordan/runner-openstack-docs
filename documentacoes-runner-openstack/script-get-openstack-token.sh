# Iniciamos carregando constantes em variáveis de ambiente que serão necessárias para o funcionamento do profile. Algumas dessas variam conforme o ambiente aonde o terraform está sendo executado.

# PARA O AMBIENTE DE DEV:

export VAULT_ADDR="http://vault.des.sicredi.net:8200"
export TF_VAR_vault_method="aws"
export TF_VAR_vault_path="auth/aws/login"
export TF_VAR_vault_parameters='{role="iac-node", region="sa-east-1", sts_region="sa-east-1"}'
export OS_PROJECT_NAME="DEV"
export OS_AUTH_TYPE="token"
export OS_AUTH_URL="https://keystone.api.dtu.infra.sicredi.net:5000/v3"
export OS_IDENTITY_API_VERSION=3
export OS_REGION_NAME="CAS"
export OS_USER_DOMAIN_NAME=sicredi
export OS_PROJECT_DOMAIN_NAME=sicredi

# autenticação no vault é feita através da IAM da instancia EC2.
# É necessário logar no vault utilizando o metodo "aws":
vault login -address=$VAULT_ADDR -method=aws role=iac-node

# Com a IAM profile, basta apenas executar o comando desejado passando o endereço do vault.
export OS_APP_CREDENTIALS=$(vault kv get -format=json -address=$VAULT_ADDR secret/stacks/gitlab-runner-terraform-openstack | jq -r '.data')

#Tendo em mãos o json com a application-credential-id e secret ou user_id e user_secret para método password, fazemos um parser para dividir as credenciais em dois variaveis de ambiente:
#APP-CREDENTIALS
export OS_APPLICATION_CREDENTIAL_ID=$(echo $OS_APP_CREDENTIALS | jq -r '.application_credential_id') 
export OS_APPLICATION_CREDENTIAL_SECRET=$(echo $OS_APP_CREDENTIALS | jq -r '.application_credential_secret')

#USER PASSWORD
export OS_USERNAME=$(echo $OS_USER_CREDENTIALS | jq -r '.user_id') 
export OS_PASSWORD=$(echo $OS_USER_CREDENTIALS | jq -r '.user_secret')

# agora podemos gerar o token temporário de acesso ao openstack através do cliente openstack:
# Existem alguma formas de autenticar para gerar token:
# Por usuário e senha:

    curl -i -s -X POST  $OS_AUTH_URL/auth/tokens?nocatalog -H "Content-Type: application/json" -d '{"auth": {"identity": {"methods": ["password"],"password": {"user": {"domain": {"name": "'"$OS_USER_DOMAIN_NAME"'"},"name": "'"$OS_USERNAME"'", "password": "'"$OS_PASSWORD"'"}}}, "scope": {"project": {"domain": {"name": "'"$OS_PROJECT_DOMAIN_NAME"'"}, "name": "'"$OS_PROJECT_NAME"'"}}}}' | python -m json.tool

# Por application credential:

    #curl -i -s -X POST  $OS_AUTH_URL/auth/tokens?nocatalog -H "Content-Type: application/json" -d '{"auth": {"identity": {"methods": ["application_credential"],"application_credential": {"id": "'"$OS_APPLICATION_CREDENTIAL_ID"'", "secret": "'"$OS_APPLICATION_CREDENTIAL_SECRET"'"}}}, "scope": {"project": {"domain": {"name": "'"$OS_PROJECT_DOMAIN_NAME"'"}, "name": "'"$OS_PROJECT_NAME"'"}}}' | python -m json.tool

# Dessa forma, teremos um output com o token vindo no header
# Portanto, otimizando o comando para nos trazer apenas o token, temos o seguinte:

export OS_TOKEN=$(curl -i -s -X POST  $OS_AUTH_URL/auth/tokens?nocatalog -H "Content-Type: application/json" -d '{"auth": {"identity": {"methods": ["password"],"password": {"user": {"domain": {"name": "'"$OS_USER_DOMAIN_NAME"'"},"name": "'"$OS_USERNAME"'", "password": "'"$OS_PASSWORD"'"}}}, "scope": {"project": {"domain": {"name": "'"$OS_PROJECT_DOMAIN_NAME"'"}, "name": "'"$OS_PROJECT_NAME"'"}}}}' | grep -i 'X-Subject-Token:' | awk '{print $2}' | tr -d '\r')

# esse token deve ser exportado para variavel OS_TOKEN

##################################################################################

# Devemos reparar que no fluxo acima, tanto o token temporário como as credenciais da aplicação cadastradas no vault são exportadas para o runner. Dessa forma acabamos pecando na questão segurança.
# Logo, temos a alternativa de unificar os cinco comandos em um único, onde as credencias do vault serão utilizadas apenas no contexto do comando, e não serão exportadas. Apenas o token com vida de 1h será exportado para o servidor. 

# OPÇÃO COM GERAÇÃO ATRAVÉS DE PASSWORD, COM USER E PASSWORD NO VAULT 

export OS_TOKEN=$( \
           OS_USER_CREDENTIALS=$( \
               VAULT_TOKEN=$( \
                   vault login -no-store -token-only -address=$VAULT_ADDR -method=aws role=iac-node \
               ) \
               vault kv get -format=json -address=$VAULT_ADDR secret/stacks/runner-terraform-openstack | jq -r '.data' \
           ) && \
           curl -v -X POST $OS_AUTH_URL/auth/tokens?nocatalog -H "Content-Type: application/json" -d "{ \
               \"auth\": { \
                   \"identity\": { \
                       \"methods\": [\"password\"], \
                       \"password\": { \
                           \"user\": { \
                               \"domain\": { \
                                   \"name\": \"$OS_USER_DOMAIN_NAME\" \
                               }, \
                               \"name\": \"$(echo $OS_USER_CREDENTIALS | jq -r '.user_id')\", \
                               \"password\": \"$(echo $OS_USER_CREDENTIALS | jq -r '.user_secret')\" \
                           } \
                       } \
                   } \
               } \
           }" | \
           grep -i 'X-Subject-Token:' | awk '{print $2}' | tr -d '\r' \
)


# OPÇÃO COM DEFINIÇÃO DE ESCOPO

export OS_TOKEN=$( \
           OS_APP_CREDENTIALS=$( \
               VAULT_TOKEN=$( \
                   vault login -no-store -token-only -address=$VAULT_ADDR -method=aws role=iac-node \
               ) \
               vault kv get -format=json -address=$VAULT_ADDR secret/stacks/runner-terraform-openstack | jq -r '.data' \
           ) && \
           curl -i -s -X POST $OS_AUTH_URL/auth/tokens?nocatalog -H "Content-Type: application/json" -d " { \
               \"auth\": { \
                   \"identity\": { \
                       \"methods\": [\"application_credential\"], \
                       \"application_credential\": { \
                           \"id\": \"$( echo $OS_APP_CREDENTIALS | jq -r '.application_credential_id' )\", \
                           \"secret\": \"$( echo $OS_APP_CREDENTIALS | jq -r '.application_credential_secret' )\" \
                       } \
                   } \
               }, \
               \"scope\": { \
                   \"project\": { \
                       \"domain\": { \
                           \"name\": \"$OS_PROJECT_DOMAIN_NAME\" \
                       }, \
                       \"name\": \"$OS_PROJECT_NAME\"
                    } \
                } \
            }" | grep -i 'X-Subject-Token:' | awk '{print $2}' | tr -d '\r'
)


# SEM DEFINIÇÃO DE ESCOPO

export OS_TOKEN=$( \
           OS_APP_CREDENTIALS=$( \
               VAULT_TOKEN=$( \
                   vault login -no-store -token-only -address=$VAULT_ADDR -method=aws role=iac-node \
               ) \
               vault kv get -format=json -address=$VAULT_ADDR secret/stacks/gitlab-runner-terraform-openstack | jq -r '.data' \
           ) && \
           curl -i -s -X POST $OS_AUTH_URL/auth/tokens?nocatalog -H "Content-Type: application/json" -d " { \
               \"auth\": { \
                   \"identity\": { \
                       \"methods\": [\"application_credential\"], \
                       \"application_credential\": { \
                           \"id\": \"$( echo $OS_APP_CREDENTIALS | jq -r '.application_credential_id' )\", \
                           \"secret\": \"$( echo $OS_APP_CREDENTIALS | jq -r '.application_credential_secret' )\" \
                       } \
                   } \
               } \
           }" | grep -i 'X-Subject-Token:' | awk '{print $2}' | tr -d '\r'
)

