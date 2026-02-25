import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import ScanPage from "@/app/scan/page"

type FetchResponse = {
  ok?: boolean
  status?: number
  json: () => Promise<unknown>
}

const createResponse = (data: unknown, ok = true, status = ok ? 200 : 500): FetchResponse => ({
  ok,
  status,
  json: async () => data
})

describe("ScanPage", () => {
  beforeEach(() => {
    global.fetch = jest.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()

      if (url.endsWith("/scan")) {
        return createResponse({
          findings: [
            {
              table: "users",
              column: "email",
              pii_type: "Email",
              confidence: 0.92,
              sample: "tes***com"
            }
          ]
        }) as Response
      }

      return createResponse({}) as Response
    }) as jest.Mock
  })

  it("sends a scan configuration payload to /scan", async () => {
    const user = userEvent.setup()
    render(<ScanPage />)

    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    await waitFor(() => {
      const fetchMock = global.fetch as jest.Mock
      expect(fetchMock).toHaveBeenCalledWith(
        "http://localhost:3001/scan",
        expect.objectContaining({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: expect.any(String)
        })
      )
    })
  })

  it("renders finding type from pii_type field", async () => {
    const user = userEvent.setup()
    render(<ScanPage />)

    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    expect(await screen.findByText("users.email")).toBeInTheDocument()
    expect(await screen.findByText("Email")).toBeInTheDocument()
  })

  it("sends custom scan connection settings from form fields", async () => {
    const user = userEvent.setup()
    render(<ScanPage />)

    await user.clear(screen.getByLabelText(/username/i))
    await user.type(screen.getByLabelText(/username/i), "alice")
    await user.clear(screen.getByLabelText(/password/i))
    await user.type(screen.getByLabelText(/password/i), "secret")
    await user.clear(screen.getByLabelText(/database/i))
    await user.type(screen.getByLabelText(/database/i), "customerdb")
    await user.clear(screen.getByLabelText(/schema/i))
    await user.type(screen.getByLabelText(/schema/i), "analytics")

    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    await waitFor(() => {
      const fetchMock = global.fetch as jest.Mock
      const scanCall = fetchMock.mock.calls.find((call) => call[0] === "http://localhost:3001/scan")
      expect(scanCall).toBeDefined()

      const scanOptions = scanCall?.[1] as RequestInit
      const body = JSON.parse(scanOptions.body as string)

      expect(body.username).toBe("alice")
      expect(body.password).toBe("secret")
      expect(body.database).toBe("customerdb")
      expect(body.schema).toBe("analytics")
    })
  })

  it("shows an error message when /scan returns non-OK", async () => {
    const user = userEvent.setup()
    const fetchMock = global.fetch as jest.Mock
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {})
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()
      if (url.endsWith("/scan")) {
        return createResponse({ error: "Authentication required", code: "auth_required" }, false, 401) as Response
      }
      return createResponse({}) as Response
    })

    render(<ScanPage />)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    expect(await screen.findByText("Authentication required")).toBeInTheDocument()
    errorSpy.mockRestore()
  })

  it("marks findings as already applied when matching persisted rules exist", async () => {
    const user = userEvent.setup()
    const fetchMock = global.fetch as jest.Mock
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString()

      if (url.endsWith("/rules")) {
        return createResponse({
          rules: [
            {
              table: "users",
              column: "email",
              strategy: "email"
            }
          ]
        }) as Response
      }

      if (url.endsWith("/scan")) {
        return createResponse({
          findings: [
            {
              table: "users",
              column: "email",
              pii_type: "Email",
              confidence: 0.92,
              sample: "tes***com"
            }
          ]
        }) as Response
      }

      return createResponse({}) as Response
    })

    render(<ScanPage />)
    await user.click(screen.getByRole("button", { name: /start new scan/i }))

    const appliedButton = await screen.findByRole("button", { name: /rule applied/i })
    expect(appliedButton).toBeDisabled()
  })
})
