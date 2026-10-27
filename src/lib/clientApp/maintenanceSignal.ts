// apiFetch fires this window event on a 503 (the middleware closes /api/*
// during maintenance); the app shell's status query listens and looks again at
// once (appStatus.ts). Its own module so apiFetch stays free of React.
export const MAINTENANCE_EVENT = "fm:maintenance";
