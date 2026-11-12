const defaultAPI = 'https://controlcenter-api.livepeer.live'

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`
}

export function bootstrapCommand(origin: string, apiURL: string, token: string) {
  const api = apiURL.replace(/\/$/, '')
  const override = api === defaultAPI ? '' : ` LIVEPEER_API_URL=${shellQuote(api)}`
  return `curl -fsSL ${shellQuote(`${origin}/bootstrap.sh`)} |${override} LIVEPEER_ENROLLMENT_TOKEN=${shellQuote(token)} sh -`
}
