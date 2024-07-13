import { type Session } from "@auth/express"

declare module "express" {
  interface Response {
    locals: {
      session?: Session
    }
  }
}

import type {AdapterUser, User, AdapterAccount } from '@auth/core/adapters'
import type {Account} from '@auth/core/types'

declare module "@auth/core/adapters" {
  interface AdapterUser extends User {
    id?: string;
    email: string;
    emailVerified?: Date | null;
    password?: string;
    roles?: string[];
    origins?: string[];
  }

  // TODO
  // type AdapterAccountTypeWithCredentials = "oauth" | "oidc" | "email" | "webauthn" | "credentials"

  // interface AdapterAccountWithCredentials extends Account {
  //   userId: string
  //   type: AdapterAccountTypeWithCredentials
  // }

  // export { AdapterAccountWithCredentials as AdapterAccount, AdapterAccountTypeWithCredentials as AdapterAccountType }
}


