import { WidgetItem } from "@/components";
// import { getServerSession } from "next-auth";
// import { authOptions } from "../api/auth/[...nextauth]/route";
import { redirect } from "next/navigation";
import { auth } from "../../../auth";

export default async function DashboardPage() {
  const session = await auth();

  if (!session) {
    redirect("/api/auth/signin");
  }

  return (
    <div className="grid gap-6 grid-cols-1">
      <WidgetItem title="Usuario conectado s-side">
        <div className="flex flex-col break-words w-full">
          <span>
            <span className="font-bold">Nombre: </span>
            {session.user?.name}
          </span>
          <span>
            <span className="font-bold">Imagen: </span>
            {session.user?.image}
          </span>
          <span>
            <span className="font-bold">Email: </span>
            {session.user?.email}
          </span>
          <span className="font-bold">User Session: </span>
          <pre
            className="break-words bg-gray-100 p-4 rounded w-full overflow-x-scroll"
            style={{ wordBreak: "break-all" }}
          >
            {JSON.stringify(session, null, 2)}
          </pre>
        </div>
      </WidgetItem>
    </div>
  );
}