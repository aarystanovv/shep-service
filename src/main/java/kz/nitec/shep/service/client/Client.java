package kz.nitec.shep.service.client;

import kz.nitec.shep.service.utils.xmlds.XmlDsUtils;
import kz.nitec.shep.userdata.ObjectFactory;
import kz.nitec.shep.userdata.Request;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.StringWriter;
import java.util.Date;
import java.util.UUID;

public class Client {

    public static void main(String[] args) {

        ObjectFactory objectFactory = new ObjectFactory();
        Request userRequest = new Request();
        userRequest.setUin("999999999999");
        userRequest.setRequestNumber(UUID.randomUUID().toString());
        userRequest.setDate(XmlDsUtils.dateToCalendar(new Date()));

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(Request.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            StringWriter writer = new StringWriter();
            marshaller.marshal(objectFactory.createRequest(userRequest), writer);
            String xml = writer.toString();

            SyncServiceClient client = new SyncServiceClient();
            client.sendMessage(xml);

        } catch (JAXBException e) {
            e.printStackTrace();
        }

    }
}
