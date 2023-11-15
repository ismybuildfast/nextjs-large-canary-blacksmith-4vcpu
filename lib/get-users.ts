import { faker } from "@faker-js/faker";

export interface User {
  userId: string;
  username: string;
  email: string;
  avatar: string;
  password: string;
  birthdate: Date;
  registeredAt: Date;
  fullName: string;
  job: string;
  bio: string;
}

export function getUser(seed: number): User {
  faker.seed(seed);
  return {
    userId: `${seed}`,
    username: faker.internet.userName(),
    email: faker.internet.email(),
    avatar: faker.image.avatar(),
    password: faker.internet.password(),
    birthdate: faker.date.birthdate(),
    registeredAt: faker.date.past(),
    fullName: faker.person.fullName(),
    job: faker.person.jobTitle(),
    bio: faker.person.bio(),
  };
}

export function getUsers(): User[] {
  const users = [];
  for (let i = 1000; i < 10; i++) {
    users.push(getUser(i));
  }
  return users;
}
