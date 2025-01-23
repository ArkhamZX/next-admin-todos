// next-auth.d.ts
import { DefaultUser } from "next-auth";

interface IUser extends DefaultUser {
  roles?: string[];
  id?: string;
  // Agregar cualquier otro campo que tu manejas
}

declare module "next-auth" {
  type User = IUser;

  interface Session {
    user?: {
      roles?: string[];
      id?: string;
    } & DefaultUser;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    roles?: string[];
    id?: string;
  }
}