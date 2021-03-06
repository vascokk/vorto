package org.eclipse.vorto.devtool.projectrepository.query;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TextFilter {

	private Object text;
	private String key;
	private String whereCondition;

	private int valueCount = 1;

	public Object getText() {
		return text;
	}

	public void setText(Object text) {
		this.text = text;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getWhereCondition() {
		return whereCondition;
	}

	public void setWhereCondition(String whereCondition) {
		this.whereCondition = whereCondition;
	}

	public void setValueCount(int valueCount) {
		this.valueCount = valueCount;
	}

	public int getValueCount() {
		return this.valueCount;
	}

	public List<Object> getParameters() {
		if (text == null) {
			return Collections.emptyList();
		}

		List<Object> parameters = new ArrayList<Object>(valueCount);
		for (int i = 0; i < valueCount; i++) {
			parameters.add(text);
		}

		return parameters;
	}

}
