
import GitHub from "@auth/express/providers/github"
import { MongoDBAdapter } from "@auth/mongodb-adapter"
import clientPromise from "../db.js"
import Credentials, { CredentialsConfig } from "@auth/express/providers/credentials"
import { User } from "@auth/express"
import { generateHash, signInSchema, compareHash, loginSchema } from "./sign-in-schema.js"
import { ExpressAuth } from "@auth/express"
import { NextFunction, Request, Response } from "express"

import type {AdapterAccountType} from '@auth/core/adapters'
import { AdapterUser } from "@auth/core/adapters"
import { AuthConfig } from "@auth/core"
import { decode, encode } from "@auth/core/jwt"
import { randomUUID } from "crypto"
import { ObjectId } from "mongodb"
import Discord from "@auth/express/providers/discord"

const mongoDbAdapter = MongoDBAdapter(clientPromise);

async function findAccount({id, provider, type}: any) {
  let query: any = {}
  if(id) {
    query.userId = new ObjectId(id)
  }
  if(provider) {
    query.provider = provider;
  }
  if(type) {
    query.type = type;
  }
  const client = await clientPromise
  return await client.db()
    .collection('accounts')
    .findOne(query)
}

const credentialProvider = (req: Request, res: Response): CredentialsConfig[] => 
{
  async function createNewUser({email, password, username}: any) {
    const avatar = `https://ui-avatars.com/api/?background=random&name=${username}&length=1`
    const user = await mongoDbAdapter.createUser!({
      email, 
      name: username, 
      password: generateHash(password),
      image: avatar,
      roles: ['user'],
      origins: [new URL(decodeURIComponent(getCookie('authjs.callback-url', req))).origin]
    })
    if (!user) {
      res.status(500).json({statusText: 'Unable to create a new user'});
      return null
    }
    const account = await mongoDbAdapter.linkAccount!({
      userId: user.id, 
      type: 'credentials' as  AdapterAccountType, 
      providerAccountId: user.id, 
      provider: 'credentials'
    })
    if (user && account) {
      return user
    }
    res.status(500).json({statusText: 'Unable to link account to created user'})
    return null;
  }

  async function signUser(user: AdapterUser, { email, password }: any) {
    if (!user.password) {
      const account: any = await findAccount({id: user.id})

      if(account) {
        res.status(405).json({statusText: `Sign in with ${account.provider}`})
      }
      else {
        res.status(500).json({statusText: 'Sign in with your oauth provider.'})
      }
      return null;
    }
    const comparePassword = compareHash(
      password,
      user.password as string
    )
    if (comparePassword) {
      return user
    }
    res.status(500).json({statusText: 'Wrong Password!'})
    return null;
  }

  return [
  Credentials({
    id: 'register',
    name: "new credentials",
    credentials: {
      username: {label: "Username", type: 'text', placeholder: "Lazar" },
      email: { label: "Email", type: "email", placeholder: "name@example.com" },
      password: { label: "Password", type: "password" },
      confirm: {label: 'Confirm', type: "password" }
    },
    authorize: async (credentials, req): Promise<User | null> => {
      try {
        if (req.method !== 'POST') {
          res.status(405).json({
            statusText: `Method ${req.method} Not Allowed`,
          })
          return null;
        }
        const { email, password, username } = await signInSchema.parseAsync(credentials)
        const user = await mongoDbAdapter.getUserByEmail!(email)
        if (user) {
          res.status(405).json({statusText: 'Please login'})
        } else {
          return await createNewUser({email, password, username})
        }
      } catch (error) {
        res.status(405).json(error)
      }
      return null;
    },

  }),
  Credentials({
    id: 'login',
    name: "existing credentials",
    credentials: {
      email: { label: "Email", type: "email", placeholder: "name@example.com" },
      password: { label: "Password", type: "password" },
    },
    authorize: async (credentials, req): Promise<User | null> => {
      try {
        if (req.method !== 'POST') {
          res.status(405).json({
            statusText: `Method ${req.method} Not Allowed`,
          })
          return null;
        }
        const { email, password } = await loginSchema.parseAsync(credentials)
        const user = await mongoDbAdapter.getUserByEmail!(email)
        if (user) {
          return await signUser(user, { email, password })
        } else {
          res.status(401).json({statusText: 'Not allowed'})
        }
      } catch (error) {
        res.status(405).json(error)
      }
      return null;
    },
})];

}

function getCookie(search: string, req: Request) {
  var cookie = req.headers.cookie;
  if(!cookie) {
    return {};
  }

  const dict = cookie.split('; ').reduce((obj, pair) => {
    const [key,value] = pair.split('=')
    obj[key] = value
    return obj;
  }, {} as any);

  return dict[search]
}

function setCookie(key: string, val: string, req: Request) {
  const dict = req.headers.cookie?.split(';').reduce((dict, pair)=> {
    const [key, value] = pair.replace(' ','').split('=')
    dict[key] = value;
    return dict
  }, {} as any)
  dict[key] = val;

  req.headers.cookie = Object.keys(dict).map(key => `${key}=${dict[key]}`).join('; ')
}

export const authConfig = (req: Request, res: Response): AuthConfig => {

  if(reqIncludes(["callback"]) && req.method === "POST") {
    console.log(
      "Handling callback request from my Identity Provider",
      {body: req.body, cookie: req.headers.cookie}
    )
  }

  function reqIncludes(arr: string[]) {
    return arr.some(str=>req.baseUrl.includes(str))
  }

  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(url => new URL(url).origin) || [];

  return {
    // debug: true,
    secret: process.env.AUTH_SECRET,
    trustHost: true,
    adapter: mongoDbAdapter,
    providers: [...credentialProvider(req,res), Discord({
      async profile(data) {
        if (data.avatar === null) {
          const defaultAvatarNumber =
            data.discriminator === "0"
              ? Number(BigInt(data.id) >> BigInt(22)) % 6
              : parseInt(data.discriminator) % 5
          data.image_url = `https://cdn.discordapp.com/embed/avatars/${defaultAvatarNumber}.png`
        } else {
          const format = data.avatar.startsWith("a_") ? "gif" : "png"
          data.image_url = `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.${format}`
        }
        return {
          id: data.id,
          name: data.global_name ?? data.username,
          email: data.email,
          image: data.image_url,
          roles: ['user'],
          origins: [new URL(decodeURIComponent(getCookie('authjs.callback-url', req))).origin]
        }
      }
    }), GitHub({
    async profile(data) {
      return {
        id: data.id.toString(),
        name: data.name ?? data.login,
        email: data.email,
        image: data.avatar_url,
        roles: ['user'],
        origins: [new URL(decodeURIComponent(getCookie('authjs.callback-url', req))).origin]
      }
    }
  })
],
  session: {
    strategy: "database", 
    maxAge: 15 * 60 // 15 minutes
    },
  callbacks: {
    async redirect({url, baseUrl}) {
      if (url.startsWith("/")) return `${baseUrl}${url}`
      const redirectOrigin = new URL(url).origin;
      if ([baseUrl, ...allowedOrigins].some(u => u === redirectOrigin)) return url
      return baseUrl;
    },
    async signIn({ user, account, profile, credentials }): Promise<any> {
      const callbackUrl = decodeURIComponent(getCookie('authjs.callback-url', req))
      const origins = (user as any)['origins'];
      if(origins.every((origin: string) => !callbackUrl.includes(origin))) {
        res.clearCookie('authjs.callback-url')
        return '/api/auth/signin' 
      }

      if(reqIncludes(['login', 'register'])) {
        if(user.id) {
          const sessionToken = randomUUID()
          const sessionMaxAge = 60 * 60 * 24 * 30
          const sessionExpiry = new Date(Date.now() + sessionMaxAge * 1000)
          await mongoDbAdapter.createSession!({sessionToken, userId: user.id, expires: sessionExpiry })
          res.cookie('authjs.session-token', sessionToken, {expires: sessionExpiry, maxAge: sessionMaxAge})
          setCookie('authjs.session-token', sessionToken, req);
          
          return true;
        }
      }

      const profileExists = await mongoDbAdapter.getUserByEmail!(user?.email || '')
      if(!profileExists) {
        return true
      }

      const accountExists = await findAccount({id: profileExists.id, provider: account?.provider})
      if(accountExists) {
        return true;
      }
      
      const creds = ['login', 'register']

      await mongoDbAdapter.linkAccount!({
        userId: profileExists.id,
        type: account!.type as AdapterAccountType,
        provider: creds.includes(account!.provider) ? 'credentials' : account!.provider,
        providerAccountId: account!.providerAccountId,
        access_token: account!.access_token,
        expires_at: account!.expires_at,
        token_type: account!.token_type,
        scope: account!.scope,
        id_token: account!.id_token,
      })

      await mongoDbAdapter.updateUser!({
        ...profileExists,
        name: user.name,
        image: user.image
      })
      return user;
    },
    async jwt({token,user}) {
      if(token.exp && Date.now() > token.exp * 1000) {
        // todo
        console.log('token expired');
      }
      if(user) token.user = user;
      return token;
    },
    async session({session, user}) {
      // todo silent refresh??
      if(user) {
        session.user = {
          id: user.id,
          name: user.name,
          email: user.email,
          image: user.image,
          roles: user.roles
        }
      }
      return session;
    }
  },
  jwt: {
    encode: async (params): Promise<any> => {
      if(reqIncludes(['login', 'register']) && req.method === 'POST') {
        return getCookie('authjs.session-token', req) || ''
      }

      return encode(params)
    },
    decode: async (params) => {
      if(reqIncludes(['login', 'register']) && req.method === 'POST') {
        return null;
      }

      return decode(params)
    },
  }
}
}

export const ExpressAuthHandler = (req: Request, res: Response, next: NextFunction) => {
  return ExpressAuth(authConfig(req, res) as any)(req, res, next)
}
