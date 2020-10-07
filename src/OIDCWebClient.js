'use strict'

const fetch = require('node-fetch')
const RelyingParty = require('@solid/oidc-rp')
const Session = require('@solid/oidc-rp/lib/Session')
const storage = require('./storage')
const authorization = require('auth-header')

// URI parameter types
const { QUERY } = require('./browser')

const DEFAULT_UI_MODE = 'popup'

class OIDCWebClient {
  /**
   * @constructor
   *
   * @param [options={}] {Object}
   *
   * @param options.popToken {boolean} Use PoP token semantics
   *
   * @param options.provider {string} Provider (issuer) URL
   *
   * @param options.defaults {Object} Relying Party registration defaults
   *
   * @param options.clients {LocalJsonStore<RelyingParty>} Relying Party registration store
   * @param options.session {LocalJsonStore<Session>} Session store
   * @param options.providers {LocalJsonStore<string>} Stores provider URI by state
   *
   * @param options.store {LocalStorage} Storage to pass to RP instances
   */
  constructor (options = {}) {
    this.popToken = options.popToken || options.solid // accept 'solid' alias

    this.defaults = options.defaults || {}

    this.browser = options.browser || require('./browser')

    this.provider = options.provider || this.defaults.issuer || null

    this.store = options.store || storage.defaultStore()

    this.clients = options.clients || storage.defaultClientStore(this.store)
    this.session = options.session || storage.defaultSessionStore(this.store)
    this.providers = options.providers || storage.defaultProviderStore(this.store)
    this.hosts = storage.defaultHostsStore(this.store)
  }

  /**
   * @returns {Promise<Session>}
   */
  async currentSession () {
    return await this.session.get() || // try loading a saved session
      await this.sessionFromResponse() || // or parse it from auth response
      Session.from({}) // failing that, return an empty session
  }

  /**
   * @param [options={}] {object}
   *
   * @param [options.provider] {string} Provider URI
   * @param [options.mode=DEFAULT_UI_MODE] {string} UI mode, popup or redirect
   *
   * @returns {Promise}
   */
  async login (options = {}) {
    switch (options.mode || DEFAULT_UI_MODE) {
      case 'redirect':
        return this.redirectTo(options)
      case 'popup':
        return this.loginPopup(options)
    }
  }

  /**
   * @param options {object}
   *
   * @param options.provider {string} Provider URI
   *
   * @returns {Promise} Currently ends in a window redirect
   */
  async redirectTo (options) {
    if (!options.provider) {
      throw new Error('Missing provider argument for redirectTo()')
    }
    const rp = await this.rpFor(options.provider, options)
    return this.sendAuthRequest(rp)
  }

  async loginPopup (options) {
    this.browser.openLoginPopup()
  }

  async logout () {
    // TODO: send a logout request to the RP
    var session = await this.currentSession()
    var idp = session.issuer
    const rp = await this.clients.get(idp)
    if (rp) {
      rp.store = this.store
      try {
        await rp.logout(session.authorization.access_token)
      } catch (err) {
      }
    }
    this.clients.clear()
    this.session.clear()
  }

  /**
   * sessionFromResponse
   *
   * @description
   * Determines if the current url has an authentication response in its
   * hash fragment, and initializes a session from it if present.
   * Resolves with an empty session otherwise.
   *
   * @returns {Promise<Session|null>}
   */
  async sessionFromResponse () {
    if (!this.browser.currentUriHasAuthResponse()) {
      return null
    }

    let responseUri = this.browser.currentLocation()

    let state = this.browser.stateFromUri(responseUri)

    const provider = await this.providers.get(state)
    if (!provider) {
      throw new Error('Could not load provider uri from response state param')
    }

    try {
      const rp = await this.rpFor(provider)

      const session = await rp.validateResponse(responseUri, this.store)
      this.browser.clearAuthResponseFromUrl()

      return await this.session.save(session) // returns session
    } catch (error) {
      console.error('Error determining current session:', error)
      return null
    }
  }

  /**
   * Open a Select Provider popup
   * @returns {Promise}
   */
  // selectProviderUI () {
  //   return Promise.resolve(null)
  // }

  /**
   * @param provider {string} Provider (issuer) url
   * @param options {object}
   *
   * @returns {Promise<RelyingParty>}
   */
  async rpFor (provider, options = {}) {
    const rp = await this.clients.get(provider)
    return rp || this.register(provider, options)
  }

  /**
   * Registers a public relying party client, saves the resulting
   * registration in the clients storage, and resolves with it (the rp instance)
   *
   * @param provider
   * @param options
   * @returns {Promise<RelyingParty>}
   */
  async register (provider, options) {
    const rp = await this.registerPublicClient(provider, options)
    return this.clients.save(provider, rp)
  }

  /**
   * @param provider
   * @param options
   * @returns {Promise<RelyingParty>}
   */
  async registerPublicClient (provider, options = {}) {
    provider = provider || options.issuer
    let redirectUri = options['redirect_uri'] || this.browser.currentLocation()

    let registration = {
      issuer: provider,
      grant_types: options['grant_types'] || ['implicit'],
      redirect_uris: [ redirectUri ],
      response_types: options['response_types'] || ['id_token token'],
      scope: options['scope'] || 'openid profile'
    }

    let rpOptions = {
      defaults: {
        popToken: this.popToken,
        authenticate: {
          redirect_uri: redirectUri,
          response_type: 'id_token token'
        }
      },
      store: this.store
    }

    return this.registerClient(provider, registration, rpOptions)
  }

  /**
   * @param provider
   * @param registration
   * @param rpOptions
   * @returns {Promise<RelyingParty>}
   */
  async registerClient (provider, registration, rpOptions) {
    return RelyingParty.register(provider, registration, rpOptions)
  }

  /**
   * @param rp {RelyingParty}
   *
   * @return {Promise}
   */
  async sendAuthRequest (rp) {
    let options = {}
    let providerUri = rp.provider.url

    const authUri = await rp.createRequest(options, this.store)

    let state = this.browser.stateFromUri(authUri, QUERY)

    await this.providers.save(state, providerUri) // save provider by state

    return this.browser.redirectTo(authUri)
  }

  async authFetch (url, options = {}) {
    const session = await this.currentSession()
    if (!session || !session.hasCredentials()) {
      return fetch(url, options)
    }

    // If we know the server expects credentials, send them
    if (await shouldShareCredentials(session, this.hosts, url)) {
      return session.fetch(url, options)
    }

    // If we don't know for sure, try a regular fetch first
    let resp = await fetch(url, options)

    // If the server then requests credentials, send them
    if (resp.status === 401) {
      await updateHostFromResponse(resp, this.hosts)
      if (await shouldShareCredentials(session, this.hosts, url)) {
        resp = session.fetch(url, options)
      }
    }
    return resp
  }
}

async function shouldShareCredentials (session, hosts, url) {
  const { host } = new URL(url.toString(), window.location.href)
  if (session && session.hasCredentials() && host === new URL(session.issuer).host) {
    return {url: host, requireAuth: true}
  }

  const requestHost = await hosts.get(host)
  return requestHost != null && requestHost.requiresAuth
}

async function updateHostFromResponse (resp, hosts) {
  if (resp.status !== 401) {
    return
  }

  const wwwAuthHeader = resp.headers.get('www-authenticate')
  if (!wwwAuthHeader) {
    return
  }

  const auth = authorization.parse(wwwAuthHeader)
  if (auth.scheme === 'Bearer' && auth.params && auth.params.scope === 'openid webid') {
    const { host } = new URL(resp.url)
    await hosts.save(host, { url: host, requiresAuth: true })
  }
}

module.exports = OIDCWebClient
