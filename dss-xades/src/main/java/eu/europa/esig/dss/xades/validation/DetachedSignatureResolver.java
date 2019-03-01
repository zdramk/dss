package eu.europa.esig.dss.xades.validation;

import java.util.List;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;

/**
 * Resolver for detached signature only.
 * 
 * The reference URI must be null or refer a specific file.
 */
public class DetachedSignatureResolver extends ResourceResolverSpi {

	private final List<DSSDocument> documents;
	private final DigestAlgorithm digestAlgorithm;

	public DetachedSignatureResolver(final List<DSSDocument> documents, DigestAlgorithm digestAlgorithm) {
		this.documents = documents;
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	public XMLSignatureInput engineResolve(Attr attr, String s) throws ResourceResolverException {
		DSSDocument document = getCurrentDocument(attr, s);
		if (document instanceof DigestDocument) {
			throw new DSSException(
				String.format("DigestDocument is not supported withing xmlsec 1.5.0: %s", document.getName()));
//			DigestDocument digestDoc = (DigestDocument) document;
//			return new PreDefinedDigestXMLSignatureInput(digestDoc.getDigest(digestAlgorithm).getBytes());
		} else {
			final XMLSignatureInput result = new XMLSignatureInput(document.openStream());
			final MimeType mimeType = document.getMimeType();
			if (mimeType != null) {
				result.setMIMEType(mimeType.getMimeTypeString());
			}
			return result;
		}
	}

	private DSSDocument getCurrentDocument(Attr attr, String baseUri) throws ResourceResolverException {
		if (definedFilename(attr) && isDocumentNamesDefined()) {
			String uriValue = DSSUtils.decodeUrl(attr.getNodeValue());
			for (DSSDocument dssDocument : documents) {
				if (Utils.areStringsEqual(dssDocument.getName(), uriValue)) {
					return dssDocument;
				}
			}
			Object[] exArgs = {"Unable to find document '" + uriValue + "' (detached signature)"};
			throw new ResourceResolverException("generic.EmptyMessage", exArgs, attr, baseUri);
		}

		if (Utils.collectionSize(documents) == 1) {
			return documents.get(0);
		}

		Object[] exArgs = {"Unable to find document (detached signature)"};
		throw new ResourceResolverException("generic.EmptyMessage", exArgs, attr, baseUri);

	}

	@Override
	public boolean engineCanResolve(Attr attr, String s) {
		return (nullURI(attr) || definedFilename(attr));
	}

	private boolean nullURI(Attr attr) {
		return attr == null || Utils.isStringBlank(attr.getNodeValue());
	}

	private boolean definedFilename(Attr attr) {
		return attr != null && Utils.isStringNotBlank(attr.getNodeValue()) && !attr.getNodeValue().startsWith("#");
	}

	private boolean isDocumentNamesDefined() {
		if (Utils.isCollectionNotEmpty(documents)) {
			for (final DSSDocument dssDocument : documents) {
				if (Utils.isStringNotEmpty(dssDocument.getName())) {
					return true;
				}
			}
		}
		return false;
	}

}