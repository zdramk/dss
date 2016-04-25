//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.22 at 10:46:08 AM CEST 
//


package eu.europa.esig.dss.jaxb.diagnostic;

import java.util.Date;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for TimestampType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TimestampType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="ProductionTime" type="{http://www.w3.org/2001/XMLSchema}dateTime"/>
 *         &lt;element name="SignedDataDigestAlgo" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="EncodedSignedDataDigestValue" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="MessageImprintDataFound" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="MessageImprintDataIntact" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="CanonicalizationMethod" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="BasicSignature" type="{http://dss.esig.europa.eu/validation/diagnostic}BasicSignatureType"/>
 *         &lt;element name="SigningCertificate" type="{http://dss.esig.europa.eu/validation/diagnostic}SigningCertificateType"/>
 *         &lt;element name="CertificateChain" type="{http://dss.esig.europa.eu/validation/diagnostic}CertificateChainType"/>
 *         &lt;element name="SignedObjects" type="{http://dss.esig.europa.eu/validation/diagnostic}SignedObjectsType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Id" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Type" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TimestampType", propOrder = {
    "productionTime",
    "signedDataDigestAlgo",
    "encodedSignedDataDigestValue",
    "messageImprintDataFound",
    "messageImprintDataIntact",
    "canonicalizationMethod",
    "basicSignature",
    "signingCertificate",
    "certificateChain",
    "signedObjects"
})
public class XmlTimestampType {

    @XmlElement(name = "ProductionTime", required = true, type = String.class)
    @XmlJavaTypeAdapter(Adapter1 .class)
    @XmlSchemaType(name = "dateTime")
    protected Date productionTime;
    @XmlElement(name = "SignedDataDigestAlgo", required = true)
    protected String signedDataDigestAlgo;
    @XmlElement(name = "EncodedSignedDataDigestValue", required = true)
    protected String encodedSignedDataDigestValue;
    @XmlElement(name = "MessageImprintDataFound")
    protected boolean messageImprintDataFound;
    @XmlElement(name = "MessageImprintDataIntact")
    protected boolean messageImprintDataIntact;
    @XmlElement(name = "CanonicalizationMethod")
    protected String canonicalizationMethod;
    @XmlElement(name = "BasicSignature", required = true)
    protected XmlBasicSignatureType basicSignature;
    @XmlElement(name = "SigningCertificate", required = true)
    protected XmlSigningCertificateType signingCertificate;
    @XmlElement(name = "CertificateChain", required = true)
    protected XmlCertificateChainType certificateChain;
    @XmlElement(name = "SignedObjects")
    protected XmlSignedObjectsType signedObjects;
    @XmlAttribute(name = "Id", required = true)
    protected String id;
    @XmlAttribute(name = "Type", required = true)
    protected String type;

    /**
     * Gets the value of the productionTime property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public Date getProductionTime() {
        return productionTime;
    }

    /**
     * Sets the value of the productionTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProductionTime(Date value) {
        this.productionTime = value;
    }

    /**
     * Gets the value of the signedDataDigestAlgo property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSignedDataDigestAlgo() {
        return signedDataDigestAlgo;
    }

    /**
     * Sets the value of the signedDataDigestAlgo property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSignedDataDigestAlgo(String value) {
        this.signedDataDigestAlgo = value;
    }

    /**
     * Gets the value of the encodedSignedDataDigestValue property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEncodedSignedDataDigestValue() {
        return encodedSignedDataDigestValue;
    }

    /**
     * Sets the value of the encodedSignedDataDigestValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEncodedSignedDataDigestValue(String value) {
        this.encodedSignedDataDigestValue = value;
    }

    /**
     * Gets the value of the messageImprintDataFound property.
     * 
     */
    public boolean isMessageImprintDataFound() {
        return messageImprintDataFound;
    }

    /**
     * Sets the value of the messageImprintDataFound property.
     * 
     */
    public void setMessageImprintDataFound(boolean value) {
        this.messageImprintDataFound = value;
    }

    /**
     * Gets the value of the messageImprintDataIntact property.
     * 
     */
    public boolean isMessageImprintDataIntact() {
        return messageImprintDataIntact;
    }

    /**
     * Sets the value of the messageImprintDataIntact property.
     * 
     */
    public void setMessageImprintDataIntact(boolean value) {
        this.messageImprintDataIntact = value;
    }

    /**
     * Gets the value of the canonicalizationMethod property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCanonicalizationMethod() {
        return canonicalizationMethod;
    }

    /**
     * Sets the value of the canonicalizationMethod property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCanonicalizationMethod(String value) {
        this.canonicalizationMethod = value;
    }

    /**
     * Gets the value of the basicSignature property.
     * 
     * @return
     *     possible object is
     *     {@link XmlBasicSignatureType }
     *     
     */
    public XmlBasicSignatureType getBasicSignature() {
        return basicSignature;
    }

    /**
     * Sets the value of the basicSignature property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlBasicSignatureType }
     *     
     */
    public void setBasicSignature(XmlBasicSignatureType value) {
        this.basicSignature = value;
    }

    /**
     * Gets the value of the signingCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSigningCertificateType }
     *     
     */
    public XmlSigningCertificateType getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * Sets the value of the signingCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSigningCertificateType }
     *     
     */
    public void setSigningCertificate(XmlSigningCertificateType value) {
        this.signingCertificate = value;
    }

    /**
     * Gets the value of the certificateChain property.
     * 
     * @return
     *     possible object is
     *     {@link XmlCertificateChainType }
     *     
     */
    public XmlCertificateChainType getCertificateChain() {
        return certificateChain;
    }

    /**
     * Sets the value of the certificateChain property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlCertificateChainType }
     *     
     */
    public void setCertificateChain(XmlCertificateChainType value) {
        this.certificateChain = value;
    }

    /**
     * Gets the value of the signedObjects property.
     * 
     * @return
     *     possible object is
     *     {@link XmlSignedObjectsType }
     *     
     */
    public XmlSignedObjectsType getSignedObjects() {
        return signedObjects;
    }

    /**
     * Sets the value of the signedObjects property.
     * 
     * @param value
     *     allowed object is
     *     {@link XmlSignedObjectsType }
     *     
     */
    public void setSignedObjects(XmlSignedObjectsType value) {
        this.signedObjects = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setId(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setType(String value) {
        this.type = value;
    }

}
