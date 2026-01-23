import axios from "axios";

const API = axios.create({
    baseURL: "http://127.0.0.1:8000",
});

export const getAlerts = () => API.get("/alerts");
export const getBlockedIPs = () => API.get("/blocked-ips");

export const unblockIP = (ip) =>
    API.post("/unblock-ip", { ip });