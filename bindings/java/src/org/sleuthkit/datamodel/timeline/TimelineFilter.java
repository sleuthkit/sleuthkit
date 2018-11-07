/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.timeline;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javafx.beans.property.Property;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.DescriptionLoD;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TimelineManager;
import org.sleuthkit.datamodel.TskData;

/**
 * Interface for timeline event filters. Filters are given to the
 * TimelineManager who interpretes them appropriately for all db queries. Since
 * the filters are primarily configured in the UI, this interface provides
 * selected, disabled and active (selected and not disabled) properties.
 */
public abstract class TimelineFilter {

	/**
	 * get the display name of this filter
	 *
	 * @return a name for this filter to show in the UI
	 */
	public abstract String getDisplayName();

	/**
	 * Get the SQL where clause corresponding to this filter.
	 *
	 * @param manager The TimelineManager to use for DB spevific parts of the
	 *                query.
	 *
	 * @return an SQL where clause (without the "where") corresponding to this
	 *         filter
	 */
	abstract String getSQLWhere(TimelineManager manager);

	public abstract TimelineFilter copyOf();

	/**
	 * Intersection (And) filter
	 *
	 * @param <S> The type of sub Filters in this IntersectionFilter.
	 */
	static class IntersectionFilter<S extends TimelineFilter> extends CompoundFilter<S> {

		IntersectionFilter(List<S> subFilters) {
			super(subFilters);
		}

		IntersectionFilter() {
			super(Collections.emptyList());
		}

		@Override
		public IntersectionFilter<S> copyOf() {
			@SuppressWarnings(value = "unchecked")
			IntersectionFilter<S> filter = new IntersectionFilter<S>((List<S>) this.getSubFilters().stream().map(TimelineFilter::copyOf).collect(Collectors.toList()));
			return filter;
		}

		@Override
		public String getDisplayName() {
			String collect = getSubFilters().stream().map(TimelineFilter::getDisplayName).collect(Collectors.joining(",", "[", "]"));
			return BundleProvider.getBundle().getString("IntersectionFilter.displayName.text") + collect;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			@SuppressWarnings(value = "unchecked")
			final IntersectionFilter<S> other = (IntersectionFilter<S>) obj;
			return areSubFiltersEqual(this, other);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			String trueLiteral = manager.getSQLWhere(null);
			String join = this.getSubFilters().stream().filter(Objects::nonNull).map((S filter) -> filter.getSQLWhere(manager)).filter((String sql) -> sql.equals(trueLiteral) == false).collect(Collectors.joining(" AND "));
			return join.isEmpty() ? trueLiteral : "(" + join + ")";
		}
	}

	/**
	 * Filter to show only events tag with the tagNames of the selected
	 * subfilters.
	 */
	public static final class TagsFilter extends UnionFilter<TagNameFilter> {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("tagsFilter.displayName.text");
		}

		@Override
		public TagsFilter copyOf() {
			TagsFilter filterCopy = new TagsFilter();
			//add a copy of each subfilter
			getSubFilters().forEach((TagNameFilter tagNameFilter) -> filterCopy.addSubFilter(tagNameFilter.copyOf()));
			return filterCopy;
		}

		public void removeFilterForTag(TagName tagName) {
			getSubFilters().removeIf((TagNameFilter subfilter) -> subfilter.getTagName().equals(tagName));
			getSubFilters().sort(Comparator.comparing(TagNameFilter::getDisplayName));
		}
	}

	/**
	 * Union(or) filter
	 *
	 * @param <SubFilterType> The type of the subfilters.
	 */
	static abstract class UnionFilter<SubFilterType extends TimelineFilter> extends TimelineFilter.CompoundFilter<SubFilterType> {

		UnionFilter(ObservableList<SubFilterType> subFilters) {
			super(subFilters);
		}

		UnionFilter() {
			super(FXCollections.<SubFilterType>observableArrayList());
		}

		public void addSubFilter(SubFilterType subfilter) {
			addSubFilter(subfilter, Comparator.comparing(TimelineFilter::getDisplayName));
		}

		protected void addSubFilter(SubFilterType subfilter, Comparator<SubFilterType> comparator) {
			if (getSubFilters().contains(subfilter) == false) {
				getSubFilters().add(subfilter);
			}
			getSubFilters().sort(comparator);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			String join = this.getSubFilters().stream().map((SubFilterType filter) -> filter.getSQLWhere(manager)).collect(Collectors.joining(" OR "));
			return join.isEmpty() ? manager.getSQLWhere(null) : "(" + join + ")";
		}
	}

	/**
	 * Event Type Filter. An instance of TypeFilter is usually a tree that
	 * parallels the event type hierarchy with one filter/node for each event
	 * type.
	 */
	public final static class TypeFilter extends UnionFilter<TypeFilter> {

		private static final Comparator<TypeFilter> comparator = Comparator.comparing(TypeFilter::getEventType);
		/**
		 * the event type this filter passes
		 */
		private final EventType eventType;

		/**
		 * private constructor that enables non recursive/tree construction of
		 * the filter hierarchy for use in TypeFilter.copyOf().
		 *
		 * @param eventType the event type this filter passes
		 * @param recursive true if subfilters should be added for each subtype.
		 *                  False if no subfilters should be added.
		 */
		private TypeFilter(EventType eventType, boolean recursive) {
			super(FXCollections.observableArrayList());
			this.eventType = eventType;
			if (recursive) {
				// add subfilters for each subtype
				for (EventType subType : eventType.getSubTypes()) {
					addSubFilter(new TypeFilter(subType), comparator);
				}
			}
		}

		/**
		 * public constructor. creates a subfilter for each subtype of the given
		 * event type
		 *
		 * @param eventType the event type this filter will pass
		 */
		public TypeFilter(EventType eventType) {
			this(eventType, true);
		}

		public EventType getEventType() {
			return eventType;
		}

		@Override
		public String getDisplayName() {
			return (EventType.ROOT_EVENT_TYPE.equals(eventType)) ? BundleProvider.getBundle().getString("TypeFilter.displayName.text") : eventType.getDisplayName();
		}

		@Override
		public TypeFilter copyOf() {
			//make a nonrecursive copy of this filter
			final TypeFilter filterCopy = new TypeFilter(eventType, false);
			//add a copy of each subfilter
			getSubFilters().forEach(subFilter -> filterCopy.getSubFilters().add(subFilter.copyOf()));
			return filterCopy;
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 17 * hash + Objects.hashCode(this.eventType);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final TypeFilter other = (TypeFilter) obj;
			if (!Objects.equals(this.eventType, other.eventType)) {
				return false;
			}
			return areSubFiltersEqual(this, other);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return "(sub_type IN (" + getSubTypeIDs().collect(Collectors.joining(",")) + "))"; //NON-NLS
		}

		private Stream<String> getSubTypeIDs() {
			if (this.getSubFilters().isEmpty()) {
				return Stream.of(String.valueOf(getEventType().getTypeID()));
			} else {
				return this.getSubFilters().stream().flatMap(TypeFilter::getSubTypeIDs);
			}
		}
	}

	/**
	 * Filter for text matching
	 */
	public static final class TextFilter extends TimelineFilter {

		private final SimpleStringProperty text = new SimpleStringProperty();

		public TextFilter() {
			this("");
		}

		public TextFilter(String text) {
			super();
			this.text.set(text.trim());
		}

		public synchronized void setText(String text) {
			this.text.set(text.trim());
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("TextFilter.displayName.text");
		}

		public synchronized String getText() {
			return text.getValue();
		}

		public Property<String> textProperty() {
			return text;
		}

		@Override
		public synchronized TextFilter copyOf() {
			return new TextFilter(getText());
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final TextFilter other = (TextFilter) obj;
			return Objects.equals(getText(), other.getText());
		}

		@Override
		public int hashCode() {
			int hash = 5;
			hash = 29 * hash + Objects.hashCode(this.text.get());
			return hash;
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			if (StringUtils.isNotBlank(this.getText())) {
				return "((med_description like '%" + this.getText() + "%')" //NON-NLS
						+ " or (full_description like '%" + this.getText() + "%')" //NON-NLS
						+ " or (short_description like '%" + this.getText() + "%'))"; //NON-NLS
			} else {
				return manager.getSQLWhere(null);
			}
		}
	}

	/**
	 * An implementation of IntersectionFilter designed to be used as the root
	 * of a filter tree. provides named access to specific subfilters.
	 */
	public static final class RootFilter extends IntersectionFilter<TimelineFilter> {

		private final HideKnownFilter knownFilter;
		private final TagsFilter tagsFilter;
		private final HashHitsFilter hashFilter;
		private final TextFilter textFilter;
		private final TypeFilter typeFilter;
		private final DataSourcesFilter dataSourcesFilter;

		public DataSourcesFilter getDataSourcesFilter() {
			return dataSourcesFilter;
		}

		public TagsFilter getTagsFilter() {
			return tagsFilter;
		}

		public HashHitsFilter getHashHitsFilter() {
			return hashFilter;
		}

		public TypeFilter getTypeFilter() {
			return typeFilter;
		}

		public HideKnownFilter getKnownFilter() {
			return knownFilter;
		}

		public TextFilter getTextFilter() {
			return textFilter;
		}

		public RootFilter(HideKnownFilter knownFilter, TagsFilter tagsFilter, HashHitsFilter hashFilter, TextFilter textFilter, TypeFilter typeFilter, DataSourcesFilter dataSourcesFilter, Collection<TimelineFilter> annonymousSubFilters) {
			super(FXCollections.observableArrayList(textFilter, knownFilter, dataSourcesFilter, tagsFilter, hashFilter, typeFilter));
			getSubFilters().removeIf(Objects::isNull);
			this.knownFilter = knownFilter;
			this.tagsFilter = tagsFilter;
			this.hashFilter = hashFilter;
			this.textFilter = textFilter;
			this.typeFilter = typeFilter;
			this.dataSourcesFilter = dataSourcesFilter;
			annonymousSubFilters.stream().filter(subFilter
					-> !(subFilter == null
					|| subFilter.equals(knownFilter)
					|| subFilter.equals(tagsFilter)
					|| subFilter.equals(hashFilter)
					|| subFilter.equals(typeFilter)
					|| subFilter.equals(textFilter)
					|| subFilter.equals(dataSourcesFilter)))
					.map(TimelineFilter::copyOf).forEach(getSubFilters()::add);
		}

		@Override
		public RootFilter copyOf() {
			Set<TimelineFilter> annonymousSubFilters
					= getSubFilters().stream().filter(subFilter
							-> !(subFilter.equals(knownFilter)
					|| subFilter.equals(tagsFilter)
					|| subFilter.equals(hashFilter)
					|| subFilter.equals(typeFilter)
					|| subFilter.equals(textFilter)
					|| subFilter.equals(dataSourcesFilter)))
							.map(TimelineFilter::copyOf).collect(Collectors.toSet());
			return new RootFilter(knownFilter.copyOf(), tagsFilter.copyOf(), hashFilter.copyOf(), textFilter.copyOf(), typeFilter.copyOf(), dataSourcesFilter.copyOf(), annonymousSubFilters);
		}

		@Override
		public int hashCode() {
			return 7;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			return areSubFiltersEqual(this, (DescriptionFilter.CompoundFilter<?>) obj);
		}
	}

	/**
	 * Filter to hide known files
	 */
	public static final class HideKnownFilter extends TimelineFilter {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hideKnownFilter.displayName.text");
		}

		public HideKnownFilter() {
			super();
		}

		@Override
		public HideKnownFilter copyOf() {
			return new HideKnownFilter();
		}

		@Override
		public int hashCode() {
			return 7;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			return getClass() == obj.getClass();
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return "(known_state != " + TskData.FileKnown.KNOWN.getFileKnownValue() + ")"; // NON-NLS
		}
	}

	/**
	 * A Filter with a collection of sub-filters. Concrete implementations can
	 * decide how to combine the sub-filters.
	 *
	 * @param <SubFilterType> The type of the subfilters.
	 */
	public static abstract class CompoundFilter<SubFilterType extends TimelineFilter> extends TimelineFilter {

		/**
		 * The list of sub-filters that make up this filter
		 */
		private final ObservableList<SubFilterType> subFilters = FXCollections.observableArrayList();

		public final ObservableList<SubFilterType> getSubFilters() {
			return subFilters;
		}

		public boolean hasSubFilters() {
			return getSubFilters().isEmpty() == false;
		}

		/**
		 * construct a compound filter from a list of other filters to combine.
		 *
		 * @param subFilters
		 */
		CompoundFilter(List<SubFilterType> subFilters) {
			super();
			this.subFilters.setAll(subFilters);
		}

		static boolean areSubFiltersEqual(final CompoundFilter<?> oneFilter, final CompoundFilter<?> otherFilter) {
			if (oneFilter.getSubFilters().size() != otherFilter.getSubFilters().size()) {
				return false;
			}
			for (int i = 0; i < oneFilter.getSubFilters().size(); i++) {
				TimelineFilter subFilter = oneFilter.getSubFilters().get(i);
				TimelineFilter otherSubFilter = otherFilter.getSubFilters().get(i);
				if (subFilter.equals(otherSubFilter) == false) {
					return false;
				}
			}
			return true;
		}

		@Override
		public abstract CompoundFilter<SubFilterType> copyOf();

		@Override
		public int hashCode() {
			int hash = 3;
			hash = 23 * hash + Objects.hashCode(this.subFilters);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final CompoundFilter<?> other = (CompoundFilter<?>) obj;
			return areSubFiltersEqual(this, other);
		}
	}

	/**
	 * Filter for events that do(not) have the given description.
	 */
	public static final class DescriptionFilter extends TimelineFilter {

		private final DescriptionLoD descriptionLoD;
		private final String description;
		private final FilterMode filterMode;

		public DescriptionFilter(DescriptionLoD descriptionLoD, String description, FilterMode filterMode) {
			super();
			this.descriptionLoD = descriptionLoD;
			this.description = description;
			this.filterMode = filterMode;
		}

		public FilterMode getFilterMode() {
			return filterMode;
		}

		@Override
		public DescriptionFilter copyOf() {
			return new DescriptionFilter(getDescriptionLoD(), getDescription(), getFilterMode());
		}

		@Override
		public String getDisplayName() {
			return getDescriptionLoD().getDisplayName() + ": " + getDescription();
		}

		/**
		 * @return the descriptionLoD
		 */
		public DescriptionLoD getDescriptionLoD() {
			return descriptionLoD;
		}

		/**
		 * @return the description
		 */
		public String getDescription() {
			return description;
		}

		/**
		 * Enum for the two modes of the DesciptionFilter, include and exclude
		 */
		public enum FilterMode {
			EXCLUDE(BundleProvider.getBundle().getString("DescriptionFilter.mode.exclude"), " NOT LIKE "),
			INCLUDE(BundleProvider.getBundle().getString("DescriptionFilter.mode.include"), " LIKE ");
			private final String like;
			private final String displayName;

			private FilterMode(String displayName, String like) {
				this.displayName = displayName;
				this.like = like;
			}

			private String getDisplayName() {
				return displayName;
			}

			private String getLike() {
				return like;
			}
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 79 * hash + Objects.hashCode(this.descriptionLoD);
			hash = 79 * hash + Objects.hashCode(this.description);
			hash = 79 * hash + Objects.hashCode(this.filterMode);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final DescriptionFilter other = (DescriptionFilter) obj;
			if (this.descriptionLoD != other.descriptionLoD) {
				return false;
			}
			if (!Objects.equals(this.description, other.description)) {
				return false;
			}
			return this.filterMode == other.filterMode;
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return "(" + manager.getDescriptionColumn(this.getDescriptionLoD()) + getFilterMode().getLike() + " '" + this.getDescription() + "'  )"; // NON-NLS
		}
	}

	/**
	 * Filter for an individual hash set
	 */
	static public final class HashSetFilter extends TimelineFilter {

		private final String hashSetName;

		public String getHashSetName() {
			return hashSetName;
		}

		public HashSetFilter(String hashSetName) {
			super();
			this.hashSetName = hashSetName;
		}

		@Override
		public synchronized HashSetFilter copyOf() {
			return new HashSetFilter(getHashSetName());
		}

		@Override
		public String getDisplayName() {
			return hashSetName;
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 79 * hash + Objects.hashCode(this.hashSetName);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final HashSetFilter other = (HashSetFilter) obj;
			return Objects.equals(this.hashSetName, other.hashSetName);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return "(hash_set_name = '" + getHashSetName() + "' )"; //NON-NLS
		}
	}

	/**
	 * Filter for an individual datasource
	 */
	public static final class DataSourceFilter extends TimelineFilter {

		private final String dataSourceName;
		private final long dataSourceID;

		public long getDataSourceID() {
			return dataSourceID;
		}

		public String getDataSourceName() {
			return dataSourceName;
		}

		public DataSourceFilter(String dataSourceName, long dataSourceID) {
			super();
			this.dataSourceName = dataSourceName;
			this.dataSourceID = dataSourceID;
		}

		@Override
		public synchronized DataSourceFilter copyOf() {
			return new DataSourceFilter(getDataSourceName(), getDataSourceID());
		}

		@Override
		public String getDisplayName() {
			return getDataSourceName() + " (ID: " + getDataSourceID() + ")";
		}

		@Override
		public int hashCode() {
			int hash = 3;
			hash = 47 * hash + Objects.hashCode(this.dataSourceName);
			hash = 47 * hash + (int) (this.dataSourceID ^ (this.dataSourceID >>> 32));
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final DataSourceFilter other = (DataSourceFilter) obj;
			if (this.dataSourceID != other.dataSourceID) {
				return false;
			}
			return Objects.equals(this.dataSourceName, other.dataSourceName);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return "(data_source_obj_id = '" + this.getDataSourceID() + "')"; //NON-NLS
		}
	}

	/**
	 * Filter for an individual TagName
	 */
	static public final class TagNameFilter extends TimelineFilter {

		private final TagName tagName;

		public TagNameFilter(TagName tagName) {
			super();
			this.tagName = tagName;
		}

		public TagName getTagName() {
			return tagName;
		}

		@Override
		public synchronized TagNameFilter copyOf() {
			return new TagNameFilter(getTagName());
		}

		@Override
		public String getDisplayName() {
			return tagName.getDisplayName();
		}

		@Override
		public int hashCode() {
			int hash = 3;
			hash = 73 * hash + Objects.hashCode(this.tagName);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final TagNameFilter other = (TagNameFilter) obj;
			return Objects.equals(this.tagName, other.tagName);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return " (tsk_events.tag_name_id = " + getTagName().getId() + " ) "; //NON-NLS
		}
	}

	/**
	 *
	 */
	static public final class HashHitsFilter extends UnionFilter<HashSetFilter> {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hashHitsFilter.displayName.text");
		}

		@Override
		public HashHitsFilter copyOf() {
			HashHitsFilter filterCopy = new HashHitsFilter();
			//add a copy of each subfilter
			this.getSubFilters().forEach((HashSetFilter hashSetFilter) -> filterCopy.addSubFilter(hashSetFilter.copyOf()));
			return filterCopy;
		}
	}

	/**
	 * union of DataSourceFilters
	 */
	static public final class DataSourcesFilter extends UnionFilter< DataSourceFilter> {

		public DataSourcesFilter() {
			super();
		}

		@Override
		public DataSourcesFilter copyOf() {
			final DataSourcesFilter filterCopy = new DataSourcesFilter();
			//add a copy of each subfilter
			getSubFilters().forEach((DataSourceFilter dataSourceFilter) -> filterCopy.addSubFilter(dataSourceFilter.copyOf()));
			return filterCopy;
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("DataSourcesFilter.displayName.text");
		}
	}
}
