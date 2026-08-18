const socket = new WebSocket("wss://example.test/socket");
const query = "query GetUser($id: ID!) { user(id: $id) { id } }";
