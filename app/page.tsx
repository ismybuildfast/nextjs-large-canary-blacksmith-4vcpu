import { getUsers } from "@/lib/get-users";
import Link from "next/link";
import { BenchmarkMarker } from "./benchmark-marker";

export default function Home() {
  const users = getUsers();

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <ul>
        {users.map((user) => (
          <li key={user.userId}>
            <Link href={`/users/${user.userId}`}>{user.username}</Link>
          </li>
        ))}
      </ul>
      <BenchmarkMarker />
    </main>
  );
}
