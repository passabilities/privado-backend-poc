import {AuthorizationRequestMessage, AuthorizationResponseMessage, BasicMessage} from '@0xpolygonid/js-sdk';
import {auth, resolver} from '@iden3/js-iden3-auth';
import {BootBindings} from '@loopback/boot';
import {inject} from '@loopback/core';
import {ParameterObject} from '@loopback/openapi-v3/dist/types';
import {get, param, post, Request, requestBody, RestBindings} from '@loopback/rest';
import path from 'path';
import getRawBody from 'raw-body';

const ISSUER_DID = process.env.POLYGONID_ISSUER_NODE_IDENTIFIER!
if (!ISSUER_DID) throw new Error('Issuer DID not defined')

const sessionIdSpec: ParameterObject = {
  name: 'sessionId',
  in: 'query',
  description: 'The ID of the authentication request',
  required: true,
  schema: { type: 'string' }
}

const didAuthSession: Map<string, {
  req: AuthorizationRequestMessage
  res: Promise<AuthorizationResponseMessage>
  resolve: (res: AuthorizationResponseMessage) => void
  reject: (reason?: never) => void
}> = new Map()


export class Iden3AgentController {
  constructor(
    @inject(BootBindings.PROJECT_ROOT) private projectRoot: string,
    @inject(RestBindings.Http.REQUEST) private req: Request,
  ) {}


  @post('/auth-request', {
    responses: {
      '200': {
        description: '',
        content: {
          'application/json': {
            schema: {
              properties: {
                id: { type: 'string' },
                typ: { type: 'string', nullable: true },
                type: { type: 'string' },
                thid: { type: 'string', nullable: true },
                body: { type: 'object' },
                from: { type: 'string' },
                to: { type: 'string' },
              }
            }
          }
        }
      }
    }
  })
  async newAuthRequest(
    @requestBody({
      content: {
        'application/json': {
          schema: {
            properties: {
              reason: {
                description: 'Reason for the request',
                type: 'string',
                default: '',
              },
              scope: {
                description: 'Array of scopes to query in authorization request',
                type: 'array',
              }
            }
          }
        }
      }
    }) body: { reason: string, scope: never[] }
  ): Promise<object> {
    const protocol = process.env.ENVIRONMENT === 'development' ? 'http' : 'https'
    const callbackUrl = `${protocol}://${this.req.get('host')}/agent`
    const request = auth.createAuthorizationRequest(body.reason, ISSUER_DID, callbackUrl)
    request.body.scope = request.body.scope.concat(body.scope)

    let resolveFn: (res: AuthorizationResponseMessage) => void
    let rejectFn: (reason?: never) => void
    const resPromise = new Promise<AuthorizationResponseMessage>((resolve, reject) => {
      resolveFn = resolve
      rejectFn = reject
    })
    didAuthSession.set(request.id, { req: request, res: resPromise, resolve: resolveFn!, reject: rejectFn! })

    return request
  }

  @get('/auth-request')
  async getAuthRequest(
    @param(sessionIdSpec) sessionId: string
  ): Promise<AuthorizationRequestMessage | { error: string }> {
    const session = didAuthSession.get(sessionId)
    if (session) return session.req

    return {
      error: `Authorization request with ID '${sessionId}' does not exist.`
    }
  }

  @get('/auth-response')
  async getAuthResponse(
    @param(sessionIdSpec) sessionId: string
  ): Promise<AuthorizationResponseMessage | { error: string }> {
    const session = didAuthSession.get(sessionId)
    if (session) return session.res

    return {
      error: `Authorization request with ID '${sessionId}' does not exist.`
    }
  }

  @post('/agent')
  async agent(): Promise<object> {
    const resolvers = {
      'polygon:amoy': new resolver.EthStateResolver(`https://polygon-amoy.g.alchemy.com/v2/${process.env.ALCHEMYAPI_MATIC_TESTNET_APIKEY}`, '0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124'),
    }

    // EXECUTE VERIFICATION
    const verifier = await auth.Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(this.projectRoot, 'constants', 'keys'),
      ipfsGatewayURL: 'https://gateway.pinata.cloud',
    })

    const responseToken = await verifier.verifyJWZ(await getRawBody(this.req).then((jwz) => jwz.toString().trim()))
    const message: BasicMessage = JSON.parse(responseToken.getPayload())

    const sessionId = message.thid ?? message.id
    const session = Object.assign({ req: message }, didAuthSession.get(sessionId))
    if (!didAuthSession.has(sessionId)) didAuthSession.set(sessionId, session)

    switch (message.type) {
      case 'https://iden3-communication.io/authorization/1.0/response': {
        // fetch authRequest from sessionID
        try {
          const response = message as AuthorizationResponseMessage
          await verifier.verifyAuthResponse(response, session.req, {
            acceptedStateTransitionDelay: 15 * 60 * 1000, // 15 minute
          })
          session.resolve(response)
        } catch (err) {
          session.reject(err)
        }

        return message
      }

      default:
        throw new Error('Unsupported message type')
    }
  }
}
