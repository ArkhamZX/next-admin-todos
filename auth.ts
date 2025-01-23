import prisma from "@/lib/prisma";
import NextAuth from "next-auth";
import {PrismaAdapter} from "@auth/prisma-adapter";
import {Adapter} from "next-auth/adapters";
import GitHub from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import {signInEmailPassword} from "@/app/auth/actions/auth-actions";

export const {handlers, signIn, signOut, auth} = NextAuth({
	adapter: PrismaAdapter(prisma) as Adapter,
	providers: [
		GitHub,
		GoogleProvider,

		CredentialsProvider({
			name: "Credentials",
			credentials: {
				email: {
					label: "Correo Electrónico",
					type: "email",
					placeholder: "usuario@google.com",
				},
				password: {
					label: "Contraseña",
					type: "password",
					placeholder: "*******",
				},
			},
			async authorize(credentials) {
				const user = await signInEmailPassword(
					credentials!.email as string,
					credentials!.password as string
				);

				if (user) {
					// Any object returned will be saved in `user` property of the JWT
					return user;
				}

				return null;
			},
		}),
	],

	session: {
		strategy: "jwt",
	},

	callbacks: {
		async signIn({user, account, profile, email, credentials}) {
			return true;
		},

		async jwt({token, user, account, profile}) {
			const dbUser = await prisma.user.findUnique({
				where: {email: token.email ?? "no-email"},
			});

			if (dbUser?.isActive === false) {
				throw Error("Usuario no está activo");
			}

			token.roles = dbUser?.roles ?? ["no-roles"];
			token.id = dbUser?.id ?? "no-id";

			return token;
		},

		async session({session, token, user}) {
			if (session && session.user) {
				session.user.roles = token.roles;
				session.user.id = token.id;
			}

			return session;
		},
	},
});
