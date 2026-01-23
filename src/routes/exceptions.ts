import { Hono } from "hono";
import { getAllExceptions } from "../db";

const exceptions = new Hono();

/**
 * GET /exceptions
 * List all account exceptions (read-only, from JSON file)
 */
exceptions.get("/", (c) => {
    const list = getAllExceptions();

    return c.json({
        exceptions: list,
        note: "Edit exceptions.json to modify this list",
    });
});

export default exceptions;
