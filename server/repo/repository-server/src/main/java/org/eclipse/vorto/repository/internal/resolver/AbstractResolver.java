/**
 * Copyright (c) 2015-2016 Bosch Software Innovations GmbH and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 * Bosch Software Innovations GmbH - Please refer to git log
 */
package org.eclipse.vorto.repository.internal.resolver;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.eclipse.vorto.core.api.model.mapping.MappingModel;
import org.eclipse.vorto.repository.api.ModelId;
import org.eclipse.vorto.repository.api.ModelInfo;
import org.eclipse.vorto.repository.api.ModelType;
import org.eclipse.vorto.repository.api.resolver.ResolveQuery;
import org.eclipse.vorto.repository.model.IModelContent;
import org.eclipse.vorto.repository.service.IModelIdResolver;
import org.eclipse.vorto.repository.service.IModelRepository;
import org.eclipse.vorto.repository.service.IModelRepository.ContentType;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class AbstractResolver implements IModelIdResolver {

	@Autowired
	protected IModelRepository repository;
	
	@Override
	public ModelId resolve(final ResolveQuery query) {
		List<ModelInfo> mappings = this.repository.search(ModelType.Mapping.name());
		Optional<ModelId> foundId = mappings.stream()
													.filter(resource -> matchesServiceKey(resource,query.getTargetPlatformKey()))
													.map(r -> doResolve(r,query))
													.filter(modelId -> Objects.nonNull(modelId)).findFirst();
		return foundId.isPresent() ? foundId.get() : null;
	}
	
	private boolean matchesServiceKey(ModelInfo resource, String targetPlatformKey) {
		IModelContent content = this.repository.getModelContent(resource.getId(), ContentType.DSL);
		return ((MappingModel)content.getModel()).getTargetPlatform().equals(targetPlatformKey);
	}
	
	protected abstract ModelId doResolve(ModelInfo mappingModelResource, ResolveQuery query);

	public IModelRepository getRepository() {
		return repository;
	}

	public void setRepository(IModelRepository repository) {
		this.repository = repository;
	}

	
}
