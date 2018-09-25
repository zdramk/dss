//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.0 
// See <a href="https://javaee.github.io/jaxb-v2/">https://javaee.github.io/jaxb-v2/</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.09.25 at 01:01:47 PM CEST 
//


package eu.europa.esig.jaxb.policy;

import java.io.Serializable;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SignatureConstraints complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SignatureConstraints"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="StructuralValidation" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="AcceptablePolicies" type="{http://dss.esig.europa.eu/validation/policy}MultiValuesConstraint" minOccurs="0"/&gt;
 *         &lt;element name="PolicyAvailable" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="PolicyHashMatch" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="AcceptableFormats" type="{http://dss.esig.europa.eu/validation/policy}MultiValuesConstraint" minOccurs="0"/&gt;
 *         &lt;element name="FullScope" type="{http://dss.esig.europa.eu/validation/policy}LevelConstraint" minOccurs="0"/&gt;
 *         &lt;element name="BasicSignatureConstraints" type="{http://dss.esig.europa.eu/validation/policy}BasicSignatureConstraints" minOccurs="0"/&gt;
 *         &lt;element name="SignedAttributes" type="{http://dss.esig.europa.eu/validation/policy}SignedAttributesConstraints" minOccurs="0"/&gt;
 *         &lt;element name="UnsignedAttributes" type="{http://dss.esig.europa.eu/validation/policy}UnsignedAttributesConstraints" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SignatureConstraints", propOrder = {
    "structuralValidation",
    "acceptablePolicies",
    "policyAvailable",
    "policyHashMatch",
    "acceptableFormats",
    "fullScope",
    "basicSignatureConstraints",
    "signedAttributes",
    "unsignedAttributes"
})
public class SignatureConstraints
    implements Serializable
{

    private final static long serialVersionUID = 1L;
    @XmlElement(name = "StructuralValidation")
    protected LevelConstraint structuralValidation;
    @XmlElement(name = "AcceptablePolicies")
    protected MultiValuesConstraint acceptablePolicies;
    @XmlElement(name = "PolicyAvailable")
    protected LevelConstraint policyAvailable;
    @XmlElement(name = "PolicyHashMatch")
    protected LevelConstraint policyHashMatch;
    @XmlElement(name = "AcceptableFormats")
    protected MultiValuesConstraint acceptableFormats;
    @XmlElement(name = "FullScope")
    protected LevelConstraint fullScope;
    @XmlElement(name = "BasicSignatureConstraints")
    protected BasicSignatureConstraints basicSignatureConstraints;
    @XmlElement(name = "SignedAttributes")
    protected SignedAttributesConstraints signedAttributes;
    @XmlElement(name = "UnsignedAttributes")
    protected UnsignedAttributesConstraints unsignedAttributes;

    /**
     * Gets the value of the structuralValidation property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getStructuralValidation() {
        return structuralValidation;
    }

    /**
     * Sets the value of the structuralValidation property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setStructuralValidation(LevelConstraint value) {
        this.structuralValidation = value;
    }

    /**
     * Gets the value of the acceptablePolicies property.
     * 
     * @return
     *     possible object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public MultiValuesConstraint getAcceptablePolicies() {
        return acceptablePolicies;
    }

    /**
     * Sets the value of the acceptablePolicies property.
     * 
     * @param value
     *     allowed object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public void setAcceptablePolicies(MultiValuesConstraint value) {
        this.acceptablePolicies = value;
    }

    /**
     * Gets the value of the policyAvailable property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getPolicyAvailable() {
        return policyAvailable;
    }

    /**
     * Sets the value of the policyAvailable property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setPolicyAvailable(LevelConstraint value) {
        this.policyAvailable = value;
    }

    /**
     * Gets the value of the policyHashMatch property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getPolicyHashMatch() {
        return policyHashMatch;
    }

    /**
     * Sets the value of the policyHashMatch property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setPolicyHashMatch(LevelConstraint value) {
        this.policyHashMatch = value;
    }

    /**
     * Gets the value of the acceptableFormats property.
     * 
     * @return
     *     possible object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public MultiValuesConstraint getAcceptableFormats() {
        return acceptableFormats;
    }

    /**
     * Sets the value of the acceptableFormats property.
     * 
     * @param value
     *     allowed object is
     *     {@link MultiValuesConstraint }
     *     
     */
    public void setAcceptableFormats(MultiValuesConstraint value) {
        this.acceptableFormats = value;
    }

    /**
     * Gets the value of the fullScope property.
     * 
     * @return
     *     possible object is
     *     {@link LevelConstraint }
     *     
     */
    public LevelConstraint getFullScope() {
        return fullScope;
    }

    /**
     * Sets the value of the fullScope property.
     * 
     * @param value
     *     allowed object is
     *     {@link LevelConstraint }
     *     
     */
    public void setFullScope(LevelConstraint value) {
        this.fullScope = value;
    }

    /**
     * Gets the value of the basicSignatureConstraints property.
     * 
     * @return
     *     possible object is
     *     {@link BasicSignatureConstraints }
     *     
     */
    public BasicSignatureConstraints getBasicSignatureConstraints() {
        return basicSignatureConstraints;
    }

    /**
     * Sets the value of the basicSignatureConstraints property.
     * 
     * @param value
     *     allowed object is
     *     {@link BasicSignatureConstraints }
     *     
     */
    public void setBasicSignatureConstraints(BasicSignatureConstraints value) {
        this.basicSignatureConstraints = value;
    }

    /**
     * Gets the value of the signedAttributes property.
     * 
     * @return
     *     possible object is
     *     {@link SignedAttributesConstraints }
     *     
     */
    public SignedAttributesConstraints getSignedAttributes() {
        return signedAttributes;
    }

    /**
     * Sets the value of the signedAttributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignedAttributesConstraints }
     *     
     */
    public void setSignedAttributes(SignedAttributesConstraints value) {
        this.signedAttributes = value;
    }

    /**
     * Gets the value of the unsignedAttributes property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedAttributesConstraints }
     *     
     */
    public UnsignedAttributesConstraints getUnsignedAttributes() {
        return unsignedAttributes;
    }

    /**
     * Sets the value of the unsignedAttributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedAttributesConstraints }
     *     
     */
    public void setUnsignedAttributes(UnsignedAttributesConstraints value) {
        this.unsignedAttributes = value;
    }

}
