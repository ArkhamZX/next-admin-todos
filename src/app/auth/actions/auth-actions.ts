import bcrypt from "bcryptjs";
import prisma from "@/lib/prisma";
import { auth } from "../../../../auth";

export const getUserSessionServer = async () => {
  const session = await auth();

  return session?.user;
};

export const signInEmailPassword = async (email: string, password: string) => {
  if (!email || !password) return null;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    const dbUser = await createUser(email, password);
    return dbUser;
  }

  if (!bcrypt.compareSync(password, user.password ?? "")) {
    return null;
  }

  return user;
};

const createUser = async (email: string, password: string) => {
  const user = await prisma.user.create({
    data: {
      email: email,
      password: bcrypt.hashSync(password),

      // extrae el username del correo y lo capitaliza
      name: email.split("@")[0].replace(/^./, (str) => str.toUpperCase()),
    },
  });

  return user;
};