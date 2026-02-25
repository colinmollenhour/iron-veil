import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import ScanPage from "@/app/scan/page"

type FetchResponse = {
  json: () => Promise<unknown>
}

const createResponse = (data: unknown): FetchResponse => ({
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
})
