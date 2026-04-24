import express from "express"
import soap from "soap"
import cors from "cors"

const app = express()

app.use(cors())
app.use(express.json({ limit: "20mb" }))

app.post("/dian/send", async (req, res) => {
    try {

        const {
            mode,
            environment,
            fileName,
            xml,
            testSetId,
            cert,
            certPassword
        } = req.body

        const wsdl =
            environment === "habilitacion"
                ? "https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc?wsdl"
                : "https://vpfe.dian.gov.co/WcfDianCustomerServices.svc?wsdl"

        const client = await soap.createClientAsync(wsdl)

        const security = new soap.WSSecurityCert(
            cert,
            certPassword,
            { hasTimeStamp: true }
        )

        client.setSecurity(security)

        let result

        if (mode === "test") {

            const [response] =
                await client.SendTestSetAsync({
                    fileName,
                    contentFile: xml,
                    testSetId
                })

            result = response

        } else {

            const [response] =
                await client.SendBillSyncAsync({
                    fileName,
                    contentFile: xml
                })

            result = response
        }

        res.json(result)

    } catch (error) {

        res.status(500).json({
            error: error.message
        })
    }
})

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
    console.log("DIAN service running on port", PORT)
})