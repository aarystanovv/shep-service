package kz.nitec.shep.service.sync;

import kz.nitec.shep.service.utils.xmlds.XmlDsUtils;
import kz.nitec.shep.userdata.ObjectFactory;
import kz.nitec.shep.userdata.Response;
import kz.nitec.shep.userdata.Status;

import javax.jws.HandlerChain;
import javax.jws.WebService;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlSeeAlso;
import java.io.StringWriter;
import java.util.Date;
import java.util.UUID;

@WebService(
        serviceName = "sync-service-endpoint",
        portName = "ISyncChannelPort",
        targetNamespace = "http://bip.bee.kz/SyncChannel/v10/Interfaces",
        endpointInterface = "kz.nitec.shep.service.sync.ISyncChannel")
@XmlSeeAlso(ObjectFactory.class)
@HandlerChain(file = "/handler.xml")
public class SyncServiceImpl implements ISyncChannel {
    public SyncSendMessageResponse sendMessage(SyncSendMessageRequest request) throws SendMessageSendMessageFaultMsg {

        SyncSendMessageResponse syncSendMessageResponse = new SyncSendMessageResponse();
        SyncMessageInfoResponse infoResponse = new SyncMessageInfoResponse();
        infoResponse.setMessageId(UUID.randomUUID().toString());
        infoResponse.setSessionId(request.getRequestInfo().getSessionId());
        infoResponse.setResponseDate(XmlDsUtils.dateToCalendar(new Date()));

        System.out.println("request data: " + (String) request.getRequestData().getData());

        StatusInfo statusInfo = new StatusInfo();
        statusInfo.setCode("Success");
        statusInfo.setMessage("ОК");
        infoResponse.setStatus(statusInfo);

        ResponseData responseData = new ResponseData();

        ObjectFactory objectFactory = new ObjectFactory();

        Response userResponse = new Response();
        Status status = new Status();
        status.setCode("SUCCESS");
        status.setMessageRu("OK");
        status.setMessageKz("OK");
        userResponse.setStatus(status);
        userResponse.setRequestNumber(UUID.randomUUID().toString());

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(Response.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            StringWriter writer = new StringWriter();
            marshaller.marshal(objectFactory.createResponse(userResponse), writer);
            String xml = writer.toString();
            responseData.setData(xml);
        } catch (JAXBException e) {
            e.printStackTrace();
        }

        syncSendMessageResponse.setResponseData(responseData);
        syncSendMessageResponse.setResponseInfo(infoResponse);

        return syncSendMessageResponse;
    }
}
