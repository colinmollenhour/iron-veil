describe("api client", () => {
  const originalEnv = process.env

  beforeEach(() => {
    jest.resetModules()
    process.env = { ...originalEnv }
    localStorage.clear()
  })

  afterAll(() => {
    process.env = originalEnv
  })

  it("builds URLs from NEXT_PUBLIC_API_BASE_URL when set", async () => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "https://api.example.com/"
    const { buildApiUrl } = await import("@/lib/api")

    expect(buildApiUrl("/health")).toBe("https://api.example.com/health")
  })

  it("adds optional API auth headers from localStorage", async () => {
    localStorage.setItem("ironveil.api_key", "secret-key")
    localStorage.setItem("ironveil.jwt", "jwt-token")

    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: "ok" }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const { apiFetch } = await import("@/lib/api")
    await apiFetch("/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ column: "email", strategy: "email" }),
    })

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:3001/rules",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-API-Key": "secret-key",
          Authorization: "Bearer jwt-token",
        }),
      }),
    )
  })
})
