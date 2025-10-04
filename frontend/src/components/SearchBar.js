import React from 'react';
import { Search } from 'lucide-react';
import './SearchBar.css';

const SearchBar = ({ value, onChange, placeholder }) => {
  return (
    <div className="search-bar">
      <Search className="search-icon" size={20} />
      <input
        type="text"
        className="search-input"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {value && (
        <button
          className="clear-button"
          onClick={() => onChange('')}
          aria-label="Clear search"
        >
          ×
        </button>
      )}
    </div>
  );
};

export default SearchBar;
