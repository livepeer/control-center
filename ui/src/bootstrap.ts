const defaultAPI = 'https://controlcenter-api.livepeer.live'

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`
}

export function bootstrapCommand(origin: string, apiURL: string, token: string, secretsURL = '') {
  const api = apiURL.replace(/\/$/, '')
  let override = api === defaultAPI ? '' : ` LIVEPEER_API_URL=${shellQuote(api)}`
  if (secretsURL && secretsURL !== 'https://controlcenter-secrets.livepeer.live') override += ` LIVEPEER_SECRETS_URL=${shellQuote(secretsURL.replace(/\/$/,''))}`
  return `curl -fsSL ${shellQuote(`${origin}/bootstrap.sh`)} |${override} LIVEPEER_ENROLLMENT_TOKEN=${shellQuote(token)} sh -`
}
