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
            {
                hasTimeStamp: true
            }
        )

        client.setSecurity(security)

        let result

        if (mode === "test") {

            const args = {
                fileName,
                contentFile: xml,
                testSetId
            }

            const [response] =
                await client.SendTestSetAsync(args)

            result = response

        } else {

            const args = {
                fileName,
                contentFile: xml
            }

            const [response] =
                await client.SendBillSyncAsync(args)

            result = response

        }

        res.json({
            success: true,
            result
        })

    } catch (error) {

        res.status(500).json({
            success: false,
            error: error.message
        })

    }

})

app.listen(3000)